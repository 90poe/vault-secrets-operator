package vaultclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/go-logr/logr"
	hvault "github.com/hashicorp/vault/api"
)

type (
	// Client struct would hold connection to Vault
	Client struct {
		ctx               context.Context
		cancelFn          context.CancelFunc
		client            vault.Client
		secretsPathPrefix string
		logger            logr.Logger
		pkis2Clean        map[string]bool
		pkis2CleanChan    chan string
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
	c := Client{
		pkis2Clean:     make(map[string]bool),
		pkis2CleanChan: make(chan string),
	}
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

	// PKI's Tidy job
	go c.pkiTidy()
	return &c, nil
}

// AddPKI2Clean would add your PKI to cleanup
func (c *Client) AddPKI2Clean(pkiPath string) {
	c.pkis2CleanChan <- pkiPath
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
	if !reflect.ValueOf(c.logger.GetSink()).IsValid() {
		return fmt.Errorf("can't use empty logger")
	}
	// verify context and cancel func
	if !reflect.ValueOf(c.ctx).IsValid() {
		return fmt.Errorf("can't use empty context")
	}
	if c.cancelFn == nil {
		return fmt.Errorf("can't use nil cancel func")
	}
	return nil
}

// pkiTidy would issue Tidy API call
func (c *Client) pkiTidy() {
	c.logger.Info("Launching PKI Tidy routine")
	// Run PKI Tidy every 24 hours
	ticker := time.NewTicker(consts.VaultPKICleanupInHours * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			c.logger.Info(fmt.Sprintf("run PKI Tidy at: %v", t))
			for pki := range c.pkis2Clean {
				err := c.issuePkiTidy(pki)
				if err != nil {
					c.logger.Error(err, fmt.Sprintf("could not issue tidy up PKI request '%s'", pki))
					c.cancelFn()
				}
			}
		case pkiPath := <-c.pkis2CleanChan:
			c.pkis2Clean[pkiPath] = true
		case <-c.ctx.Done():
			return
		}
	}
}

// cleanup PKI CA cache from obsoleted certs
func (c *Client) issuePkiTidy(pki string) error {
	data := make(map[string]interface{}, 3)
	data["tidy_cert_store"] = true
	data["tidy_revoked_certs"] = true
	data["safety_buffer"] = "1h"
	_, err := c.client.Write(fmt.Sprintf("%s/tidy", pki), data)
	if err != nil {
		return fmt.Errorf("can't tidy up: %w", err)
	}
	return nil
}

// splitCN will split CN into first part till first \. and rest domain name
func (c *Client) splitCN(cn string) (first string, domain string, err error) {
	re := regexp.MustCompile(consts.CNParserRegexp)
	splitArr := re.FindStringSubmatch(cn)
	if splitArr == nil {
		err = fmt.Errorf("CN='%s' doesn't match regexp `%s`", cn, consts.CNParserRegexp)
		return
	}
	first = splitArr[1]
	domain = splitArr[2]
	return
}

// GetCertFromCache will fetch certificates from cache
// it will return: Cert, Key, CA, error if occured
func (c *Client) GetCertFromCache(pkiPath string, cn string) (cert, key, ca string, err error) {
	// 1. make paths to vault cache
	var (
		name, domain string
		secret       *hvault.Secret
	)
	name, domain, err = c.splitCN(cn)
	if err != nil {
		return
	}
	path2Read := filepath.Join("/v1", consts.CertCachePath, pkiPath, domain, name)
	secret, err = c.client.Read(path2Read)
	if err != nil {
		return
	}
	if secret == nil {
		err = &CacheMiss{
			name: cn,
		}
		return
	}
	return readCertValues(secret)
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
		case "private_key":
			// nolint
			key = v.(string)
		case "certificate":
			// nolint
			cert = v.(string)
		case "issuing_ca":
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
	url := fmt.Sprintf("%s/v1/%s/crl/pem", c.client.Address(), pkiPath)
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("can't get crl for %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("can't get crl data from %s. Status is %v", url, resp.StatusCode)
	}
	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read crl data from %s: %w", url, err)
	}
	crl, err := x509.ParseRevocationList(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return crl, nil
}
