package vaultclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/90poe/vault-secrets-operator/internal/certificates"
	"github.com/90poe/vault-secrets-operator/internal/consts"
	"github.com/90poe/vault-secrets-operator/internal/vault"
	"github.com/go-logr/logr"
	hvault "github.com/hashicorp/vault/api"
)

const (
	certCAPemKey  = "issuing_ca"
	certPemKey    = "certificate"
	certKeyPemKey = "private_key"
)

type (
	// Client struct would hold connection to Vault
	Client struct {
		client            vault.Client
		secretsPathPrefix string
		tlsCertsCachePath string
		logger            logr.Logger
	}
	CacheMiss struct {
		name string
	}
)

func (c *CacheMiss) Error() string {
	return fmt.Sprintf("cache missed for certificate with CN='%s'", c.name)
}

// New would create Vault Client
func New(options ...Option) (*Client, error) {
	c := Client{}
	var err error
	for _, option := range options {
		err = option(&c)
		if err != nil {
			return nil, fmt.Errorf("can't make new Vault Client: %w", err)
		}
	}
	err = c.verify()
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// GetSecret would return string (if found), bool that secret is base64 binary,
// error if something gets wrong
func (c *Client) GetSecret(secretPath string) (string, bool, error) {
	secretPath = path.Join(c.secretsPathPrefix, secretPath)

	return c.getSecretRaw(secretPath)
}

// DeleteSecret would delete secret from Vault
func (c *Client) DeleteSecret(fullPath string) error {
	_, err := c.client.Delete(fullPath)
	if err != nil {
		return fmt.Errorf("can't delete secret at path '%s': %w", fullPath, err)
	}
	return nil
}

// CreateSecret would create secret in Vault
func (c *Client) CreateSecret(fullPath string, data map[string]interface{}) error {
	_, err := c.client.Write(fullPath, data)
	if err != nil {
		return fmt.Errorf("can't write secret to path '%s': %w", fullPath, err)
	}
	return nil
}

func (c *Client) getSecretRaw(fullPath string) (string, bool, error) {
	isBinary := false
	// Get raw secret from Vault
	secret, err := c.client.Read(fullPath)
	if err != nil {
		return "", isBinary, err
	}
	if secret == nil {
		return "", isBinary, fmt.Errorf("no such secret at path '%s'", fullPath)
	}
	// Read secret, as we know format we expect
	value, ok := secret.Data[consts.VaultPlainValueKey]
	if !ok {
		value, ok = secret.Data[consts.VaultBase64ValueKey]
		if !ok {
			return "", isBinary, fmt.Errorf("can't get secrets value")
		}
		isBinary = true
	}
	sValue, ok := value.(string)
	if !ok {
		return "", isBinary, fmt.Errorf("can't get secrets value")
	}
	if len(sValue) == 0 {
		return "", isBinary, fmt.Errorf("secrets value is empty")
	}
	return sValue, isBinary, nil
}

func (c *Client) verify() error {
	if !reflect.ValueOf(c.client).IsValid() {
		return fmt.Errorf("can't use empty vault client")
	}
	if !reflect.ValueOf(c.logger.GetSink()).IsValid() {
		return fmt.Errorf("can't use empty logger")
	}
	return nil
}

// PKIAutoTidy cleanup PKI CA cache from obsoleted certs
func (c *Client) PKIAutoTidy(pki string) error {
	c.logger.V(1).Info("Add PKI Auto-Tidy for PKI", "pki", pki)
	data := make(map[string]interface{}, 3)
	data["enabled"] = true
	data["tidy_revocation_queue"] = true
	data["tidy_revoked_cert_issuer_associations"] = true
	data["tidy_cert_store"] = true
	data["tidy_revoked_certs"] = true
	data["safety_buffer"] = "1h"
	data["interval_duration"] = "24h"
	_, err := c.client.Write(fmt.Sprintf("%s/config/auto-tidy", pki), data)
	if err != nil {
		return err
	}
	return nil
}

// GetCertFromCache will fetch certificates from cache
// it will return: Cert, Key, CA, error if occured
func (c *Client) GetCertFromCache(pkiPath string, cn string) (string, string, string, error) {
	// 1. make paths to vault cache
	path2Read, err := c.makeCacheCertPath(pkiPath, cn)
	if err != nil {
		return "", "", "", fmt.Errorf("can't get path to delete for %s/%s: %w", pkiPath, cn, err)
	}
	secret, err := c.client.Read(path2Read)
	if err != nil {
		return "", "", "", err
	}
	if secret == nil {
		return "", "", "", &CacheMiss{
			name: cn,
		}
	}
	return readCertValues(secret)
}

// DelCertFromCache will delete certificate with pkiPath from cache
func (c *Client) DelCertFromCache(pkiPath string, cn string) error {
	path2Delete, err := c.makeCacheCertPath(pkiPath, cn)
	if err != nil {
		return fmt.Errorf("can't get path to delete for %s/%s: %w", pkiPath, cn, err)
	}
	_, err = c.client.Delete(path2Delete)
	if err != nil {
		return fmt.Errorf("can't delete cached certificate for %s/%s: %w", pkiPath, cn, err)
	}
	return nil
}

// PutToCache will put to cache certificate
func (c *Client) PutToCache(pkiPath, cn string, cert *certificates.Certificate) error {
	path2put, err := c.makeCacheCertPath(pkiPath, cn)
	if err != nil {
		return fmt.Errorf("can't get path to put for %s/%s: %w", pkiPath, cn, err)
	}
	_, err = c.client.Write(path2put, map[string]interface{}{
		certCAPemKey:  cert.IssuingCA,
		certPemKey:    cert.PemCert,
		certKeyPemKey: cert.PemKey,
	})
	if err != nil {
		return fmt.Errorf("can't write cert to cache %s/%s: %w", pkiPath, cn, err)
	}
	return nil
}

// makeCacheCertPath will make final certificate cache path
func (c *Client) makeCacheCertPath(pkiPath string, cn string) (string, error) {
	re := regexp.MustCompile(consts.CNParserRegexp)
	splitArr := re.FindStringSubmatch(cn)
	if splitArr == nil {
		return "", fmt.Errorf("CN='%s' doesn't match regexp `%s`", cn, consts.CNParserRegexp)
	}
	name := splitArr[1]
	domain := splitArr[2]
	return filepath.Join(c.tlsCertsCachePath, pkiPath, domain, name), nil
}

// GetSignedCertificate is central point to come for new certificate, which might be provided from cache, signed by PKI's CA
// We will return certificate
func (c *Client) GetSignedCertificate(
	pkiPath string,
	pkiRole string,
	certReq *certificates.Certificate) (*certificates.Certificate, error) {
	// 1. Check cert is in cache (vault path) so we can return it quickly (if it's not revoked)
	// 2. Create a Private Key and Certificate
	// 3. Sign certificate in PKI
	// 4. Put it into cache (vault path)
	// 5. Return cert

	// 1. Check cert is in cache
	if ok := c.checkCertInCache(pkiPath, certReq); ok {
		return certReq, nil
	}
	// 2. Create a Private Key and Certificate
	certReq, err := c.createSignedCert(pkiPath, pkiRole, certReq)
	if err != nil {
		return nil, err
	}
	return certReq, nil
}

func (c *Client) createSignedCert(pkiPath string, pkiRole string, cert *certificates.Certificate) (*certificates.Certificate, error) {
	err := cert.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("can't generate private key for cert %s: %w", cert.CommonName, err)
	}
	csr, err := cert.GenerateCSR()
	if err != nil {
		return nil, fmt.Errorf("can't generate CSR for cert %s: %w", cert.CommonName, err)
	}
	// 1. Lets make a valid URL to call
	url := filepath.Join("/", pkiPath, "sign", pkiRole)
	// Lets prepare data for a call
	data := make(map[string]interface{}, 3)
	data["csr"] = csr
	data["common_name"] = cert.CommonName
	data["not_after"] = cert.ValidUntil.UTC().Format("2006-01-02T15:04:05Z")
	// Call Vault
	vaultCertSecret, err := c.client.Write(url, data)
	// Check response is correct
	if err != nil || vaultCertSecret == nil {
		return nil, fmt.Errorf("can't request for a new cert with cn=%s: %w", cert.CommonName, err)
	}
	// Extract needed bits
	certout, _, ca, err := readCertValues(vaultCertSecret)
	if err != nil {
		return nil, fmt.Errorf("can't get certificate data for a new cert with cn=%s: %w", cert.CommonName, err)
	}
	cert.IssuingCA = ca
	cert.PemCert = certout
	return cert, nil
}

func (c *Client) checkCertInCache(pkiPath string, certReq *certificates.Certificate) bool {
	// TODO: implement check in cache
	return false
}

// readCertValues would return Certificate values
func readCertValues(secret *hvault.Secret) (cert, key, ca string, err error) {
	if secret == nil {
		err = fmt.Errorf("secret is nil")
		return
	}
	for k, v := range secret.Data {
		if reflect.TypeOf(v).Kind() != reflect.String {
			// continue as we might get interfaces here too
			continue
		}
		switch k {
		case certKeyPemKey:
			// nolint
			key = v.(string)
		case certPemKey:
			// nolint
			cert = v.(string)
		case certCAPemKey:
			// nolint
			ca = v.(string)
		}
	}
	return
}

// GetCRL would return CRL
func (c *Client) GetCRL(pkiPath string) (*x509.RevocationList, error) {
	tr := &http.Transport{
		// nolint
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("%s/v1/%s/crl", c.client.Address(), pkiPath)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("can't get crl for %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("can't get crl data from %s. Status is %v", url, resp.StatusCode)
	}
	derBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read crl data from %s: %w", url, err)
	}
	crl, err := x509.ParseRevocationList(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return crl, nil
}
