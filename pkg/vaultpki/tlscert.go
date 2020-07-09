package vaultpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"reflect"
	"strings"
	"time"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/pkg/apis/xo/v1alpha1"
	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
)

// TLSCert is data structure would hold certificate from Vault PKI
type TLSCert struct {
	//Public data
	Certificate          string
	PrivateKey           string
	IssuingCACertificate string
	SerialNumber         string
	// Private data
	profile           string
	domain            string
	pkiPath           string
	pkiCachePath      string
	pkiRole           string
	defaultTTLInHours string
	cnFQDN            string
	client            *vault.Client
}

// New will make new TLSCert with options
func New(options ...Option) (*TLSCert, error) {
	var t TLSCert
	var err error
	for _, option := range options {
		err = option(&t)
		if err != nil {
			return nil, fmt.Errorf("can't make new TLSCert: %w", err)
		}
	}
	return &t, nil
}

//GetData would make Vault API calls and return issued certificate
func (t *TLSCert) GetData(tlsReq *xov1alpha1.TLSCertificate) error {
	err := t.getPKIProfile(tlsReq)
	if err != nil {
		return err
	}
	//Try to get certificate from Cache first
	t.cnFQDN = fmt.Sprintf("%s.%s", tlsReq.CommonName, t.domain)
	ok := false
	ok, err = t.getCertFromCache()
	if err != nil {
		return fmt.Errorf("can't read cached certs: %w", err)
	}
	errMsg := "can't generate Certificate: %w"
	if ok {
		//we have cert in cache and it's valid
		return t.populateSerialNr()
	}
	// log.Printf("[%s] Cache missed, creating cert", logging.DEBUG)
	if !tlsReq.IntermediateCA {
		err = t.generateCertificate(tlsReq)
	} else {
		// we need to generate Intermediate CA
		err = t.generateIntermediatePEM(tlsReq)
		errMsg = "can't generate Intermediate: %w"
	}
	// Check for errors
	if err != nil {
		return fmt.Errorf(errMsg, err)
	}
	// Put certificate to cache for further use
	err = t.putCert2Cache()
	if err != nil {
		return fmt.Errorf("can't write generated secret to cache: %w", err)
	}
	// Populate serialNR
	return t.populateSerialNr()
}

// RevokeCertificate is going to revoke certificate from Vault
func (t *TLSCert) RevokeCertificate(tlsReq *xov1alpha1.TLSCertificate,
	serials map[string]string) error {
	err := t.getPKIProfile(tlsReq)
	if err != nil {
		return err
	}
	t.cnFQDN = fmt.Sprintf("%s.%s", tlsReq.CommonName, t.domain)
	serial, ok := serials[t.cnFQDN]
	if !ok {
		return fmt.Errorf("can't find serial for certificate %s", t.cnFQDN)
	}
	logical := t.client.Logical()
	data := make(map[string]interface{}, 1)
	data["serial_number"] = strings.ReplaceAll(serial,
		consts.TLSSerialHumanSeparator, consts.TLSSerialVaultSeparator)
	_, err = logical.Write(fmt.Sprintf("%s/revoke", t.pkiPath), data)
	if err != nil {
		return fmt.Errorf("can't revoke certificate with serial %s: %w",
			serial, err)
	}
	return nil
}

// GetCN will return CommonName of certificate
func (t *TLSCert) GetCN() string {
	return t.cnFQDN
}

// Function is called on fully populated TLSCert structure
func (t *TLSCert) populateSerialNr() error {
	cert, err := certificates.GetRawCertificate(t.Certificate)
	if err != nil {
		return fmt.Errorf("can't populate serial: %w", err)
	}
	t.SerialNumber = certutil.GetHexFormatted(cert.SerialNumber.Bytes(),
		consts.TLSSerialHumanSeparator)
	return nil
}

// generatePrivateKey would generate Private Key in crypto.Signer interface
// (A *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey satisfies this.)
// Default is ec-Prime256-1 algorithm private key
func (t *TLSCert) generatePrivateKey(tlsReq *xov1alpha1.TLSCertificate) (crypto.Signer, error) {
	switch tlsReq.IntermediateCAPrivateKeyAlgorith {
	case consts.PKIKeyAlgRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case consts.PKIKeyAlgRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		// Default is ec-Prime256-1
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
}

// Function would read all required variables from PKI profile or fail
func (t *TLSCert) getPKIProfile(tlsReq *xov1alpha1.TLSCertificate) error {
	//Get data from profile
	var err error
	secret, err := t.client.GetRawSecret(path.Join(consts.OperatorSecretsInVaultPath,
		"profiles", t.profile))
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	t.defaultTTLInHours, err = t.client.GetSecretData(secret, consts.PKIDefaultTTL)
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	t.domain, err = t.client.GetSecretData(secret, consts.PKIDomain)
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	t.pkiPath, err = t.client.GetSecretData(secret, consts.PKIPath)
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	t.pkiCachePath, err = t.client.GetSecretData(secret, consts.PKICachePath)
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	// Add PKI to scheduled cleanup
	t.client.AddPKI2Clean(t.pkiPath)
	t.pkiRole, err = t.client.GetSecretData(secret, consts.PKIRole)
	if err != nil {
		return fmt.Errorf("requesting profile: %w", err)
	}
	return nil
}

func (t *TLSCert) generateCertificate(tlsReq *xov1alpha1.TLSCertificate) error {
	//Get certificates
	var err error
	data := make(map[string]interface{})
	data["common_name"] = t.cnFQDN
	// By default we expect TTL (in hours)
	sCertTTL := fmt.Sprintf("%d", tlsReq.TTL)
	if tlsReq.TTL == 0 {
		// If TTL not specified, getting default TTL from profile
		sCertTTL = t.defaultTTLInHours
	}
	if tlsReq.MaxTTL {
		// MaxTTL is specified, so we will get max available TTL from CA
		certTTL, err := t.getMaxTTL()
		if err != nil {
			return fmt.Errorf("requesting max TTL: %w", err)
		}
		sCertTTL = fmt.Sprintf("%d", certTTL)
	}
	data["ttl"] = fmt.Sprintf("%sh", sCertTTL)
	logical := t.client.Logical()
	secret, err := logical.Write(fmt.Sprintf("%s/issue/%s", t.pkiPath,
		t.pkiRole), data)
	if err != nil {
		return fmt.Errorf("requesting certificate: %w", err)
	}
	cert, key, ca, err := t.parseCertValuesFromSecret(secret)
	if err != nil {
		return fmt.Errorf("can't read generated secret: %w", err)
	}
	// Fill in internal structures
	t.Certificate = cert
	t.PrivateKey = key
	t.IssuingCACertificate = ca
	return nil
}

//parseCertValuesFromSecret would return Certificate values
func (t *TLSCert) parseCertValuesFromSecret(secret *api.Secret) (cert,
	key, ca string, err error) {
	if secret == nil {
		return "", "", "", fmt.Errorf("secret is nil")
	}
	for k, v := range secret.Data {
		if reflect.TypeOf(v).Kind() != reflect.String {
			return "", "", "", fmt.Errorf("secret is nil")
		}
		switch k {
		case "private_key":
			key = v.(string)
		case "certificate":
			cert = v.(string)
		case "issuing_ca":
			ca = v.(string)
		}
	}
	return cert, key, ca, nil
}

//This function assumes that Data structure is semi filled with at least d.Domain
// It would fill in d.PrivateKey, d.Certificate, d.IssuingCACertificate
// Few cases about cache invalidation
// 1. When Cert TTL is expired - remove from cache
// 2. When Cert is Revoked - remove from cache
func (t *TLSCert) getCertFromCache() (bool, error) {
	path2Read := path.Join(consts.TLSCachePath, t.pkiCachePath, t.cnFQDN)
	secret, err := t.client.GetRawSecret(path2Read)
	if err != nil {
		return false, fmt.Errorf("can't read cached secret: %w", err)
	}
	if secret == nil {
		return false, nil
	}
	cert, key, ca, err := t.parseCertValuesFromSecret(secret)
	if err != nil {
		return false, fmt.Errorf("can't read cached secret: %w", err)
	}
	t.Certificate = cert
	t.PrivateKey = key
	t.IssuingCACertificate = ca
	valid, err := t.isCertValid()
	if err != nil {
		return false, err
	}
	if !valid {
		//Invalid Certificate
		t.Certificate = ""
		t.PrivateKey = ""
		t.IssuingCACertificate = ""
		err = t.deleteCachedCert()
		if err != nil {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

//This function assumes that Data structure is fully filled with all values
// It would use values from d.Domain, d.PrivateKey, d.Certificate, d.IssuingCACertificate
func (t *TLSCert) putCert2Cache() error {
	data := make(map[string]interface{})
	data["private_key"] = t.PrivateKey
	data["certificate"] = t.Certificate
	data["issuing_ca"] = t.IssuingCACertificate
	path2Write := path.Join(consts.TLSCachePath, t.pkiCachePath, t.cnFQDN)
	err := t.client.CreateSecret(path2Write, data)
	if err != nil {
		return fmt.Errorf("can't write cached secret: %w", err)
	}
	return nil
}

//This function assumes that Data structure is fully filled with all values
// It would use values from d.Domain, d.PrivateKey, d.Certificate, d.IssuingCACertificate
func (t *TLSCert) isCertValid() (bool, error) {
	crl, err := t.getCRL()
	if err != nil {
		return false, err
	}
	fullCert := strings.Join([]string{t.Certificate, t.PrivateKey}, "\n")
	valid, cn, err := certificates.IsCertificateValid(fullCert, crl)
	if err != nil {
		return false, err
	}
	if !valid {
		return valid, nil
	}
	if cn != fmt.Sprintf("CN=%s", t.cnFQDN) {
		//Certificate is not one we expect CN is different
		return false, fmt.Errorf("invalid cert CN '%s', expected 'CN=%s'",
			cn, t.cnFQDN)
	}
	return true, nil
}

//deleteCachedCert would delete cached certificate from cache in Vault
func (t *TLSCert) deleteCachedCert() error {
	path2Del := path.Join(consts.TLSCachePath, t.cnFQDN)
	err := t.client.DeleteSecret(path2Del)
	if err != nil {
		return fmt.Errorf("can't delete cached secret: %w", err)
	}
	return nil
}

//GetMaxTTL would get CA cert from PKI and would get Max TTL which could be applied for Cert in Hours
func (t *TLSCert) getMaxTTL() (uint, error) {
	caCert, err := t.getCA()
	if err != nil {
		return 0, err
	}
	now := time.Now()
	diff := caCert.NotAfter.Sub(now)
	return uint(diff.Hours()), nil
}

func (t *TLSCert) getCA() (*x509.Certificate, error) {
	url := fmt.Sprintf("%s/v1/%s/ca/pem", t.client.Address(), t.pkiPath)
	tr := &http.Transport{}
	if t.client.SkipVerify() {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Timeout:   consts.VaultClientTimeoutSec * time.Second,
		Transport: tr,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	pemCert, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return certificates.GetRawCertificate(string(pemCert))
}

//getCRL would return CRL
func (t *TLSCert) getCRL() (*pkix.CertificateList, error) {
	url := fmt.Sprintf("%s/v1/%s/crl/pem", t.client.Address(), t.pkiPath)
	tr := &http.Transport{}
	if t.client.SkipVerify() {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Timeout:   consts.VaultClientTimeoutSec * time.Second,
		Transport: tr,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("can't get crl for %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("can't get crl data from %s. Status is %v", url, resp.StatusCode)
	}
	pemBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read crl data from %s: %w", url, err)
	}
	crl, err := x509.ParseCRL(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return crl, nil
}
