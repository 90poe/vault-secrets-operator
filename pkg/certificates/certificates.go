package certificates

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/hashicorp/vault/sdk/helper/certutil"
)

const (
	CertificateRSA   = "rsa"
	CertificateEC    = "ec"
	CertificateECDSA = "ecdsa"
)

type (
	// Certificate is representation of x509.Certificate
	Certificate struct {
		Serial     string
		CommonName string
		AltNames   []string
		Issuer     string
		Type       string
		ECDSACurve string
		KeyBits    int
		ValidFrom  time.Time
		ValidUntil time.Time
		PrivateKey any
		IssuingCA  string
		PemCert    string
		PemKey     string
		Revoked    bool
	}
)

// NewCertificate would convert x509 Certificate to Certificate
func NewCertificate(cert *x509.Certificate, revoked bool) *Certificate {
	sn := certutil.GetHexFormatted(cert.SerialNumber.Bytes(), "-")
	return &Certificate{
		Serial:     sn,
		CommonName: cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		ValidFrom:  cert.NotBefore,
		ValidUntil: cert.NotAfter,
		Revoked:    revoked,
	}
}

func GetCertificateFromPem(cert, key, ca string, crl *x509.RevocationList) (*Certificate, error) {
	valid := true
	if crl != nil {
		valid, cn, err := IsCertificateValid(cert, crl)
		if err != nil {
			return nil, err
		}
		if !valid {
			return nil, &CertificateInvalid{
				cn: cn,
			}
		}
	}
	tlsCert, err := LoadCertPair([]byte(cert), []byte(key))
	if err != nil {
		return nil, err
	}
	certType, certLength, err := GetPrivateKeyTypeAndBitLenght(tlsCert)
	if err != nil {
		return nil, err
	}
	cert2Ret := &Certificate{
		Serial:     certutil.GetHexFormatted(tlsCert.Leaf.SerialNumber.Bytes(), "-"),
		CommonName: tlsCert.Leaf.Subject.String(),
		AltNames:   tlsCert.Leaf.DNSNames,
		Issuer:     tlsCert.Leaf.Issuer.String(),
		Type:       certType,
		KeyBits:    certLength,
		ValidFrom:  tlsCert.Leaf.NotBefore,
		ValidUntil: tlsCert.Leaf.NotAfter,
		PrivateKey: tlsCert.PrivateKey,
		IssuingCA:  ca,
		PemCert:    cert,
		PemKey:     key,
		Revoked:    valid,
	}
	if cert2Ret.Type == consts.CertTypeECDCA {
		cert2Ret.ECDSACurve = fmt.Sprintf("p%v", certLength)
	}

	return cert2Ret, nil
}

// GetRawCertificate would return certificate from string
func GetRawCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

func LoadCertPair(cert, key []byte) (*tls.Certificate, error) {
	certParsed, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	certParsed.Leaf, err = GetRawCertificate(string(cert))
	if err != nil {
		return nil, err
	}
	return &certParsed, nil
}

func GetPrivateKeyTypeAndBitLenght(cert *tls.Certificate) (string, int, error) {
	var bitLen int
	var keyType string
	var err error
	switch privKey := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		keyType = consts.CertTypeRSA
		bitLen = privKey.N.BitLen()
	case *ed25519.PrivateKey:
		keyType = consts.CertTypeEC
		bitLen = 256
	case *ecdsa.PrivateKey:
		keyType = consts.CertTypeECDCA
		bitLen = privKey.Curve.Params().BitSize
	default:
		// Unsuported private key
		err = fmt.Errorf("unsuported private key for cert with CN=%s", cert.Leaf.Issuer.CommonName)
	}
	return keyType, bitLen, err
}

// IsCertificateInRevokedList would check if cert is in revoked certificates list
func IsCertificateInRevokedList(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, revokedCert := range crl.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// IsCertificateValid would verify if:
// 1. Certificate is not expired
// 2. Certificate is not in revokation list
// It would return true and certificate CN
func IsCertificateValid(pem string, crl *x509.RevocationList) (bool, string, error) {
	rawCert, err := GetRawCertificate(pem)
	if err != nil {
		return false, "", err
	}
	revoked := IsCertificateInRevokedList(rawCert, crl)
	if revoked {
		return false, rawCert.Subject.CommonName, err
	}
	certInfo := NewCertificate(rawCert, revoked)

	now := time.Now()
	if now.Before(certInfo.ValidFrom) || now.After(certInfo.ValidUntil) {
		// Certificate is either expired or not yet valid
		return false, certInfo.CommonName, fmt.Errorf("%s: certificate expired", certInfo.CommonName)
	}
	return true, certInfo.CommonName, nil
}

func (c *Certificate) SetParsedPrivateKey(privateKey crypto.Signer, privateKeyType certutil.PrivateKeyType, privateKeyBytes []byte) {
	c.PrivateKey = privateKey
	c.PemKey = string(privateKeyBytes)
	c.Type = string(privateKeyType)
}

func (c *Certificate) GeneratePrivateKey() error {
	var err error
	switch c.ECDSACurve {
	case "":
		if c.Type != CertificateRSA {
			_, c.PrivateKey, err = ed25519.GenerateKey(rand.Reader)
		} else {
			c.PrivateKey, err = rsa.GenerateKey(rand.Reader, c.KeyBits)
		}
	case "p224":
		c.PrivateKey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "p256":
		c.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		c.PrivateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		c.PrivateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		err = fmt.Errorf("unrecognized elliptic curve: %q", c.ECDSACurve)
	}
	if err != nil {
		return fmt.Errorf("can't generate private key for certificate: %w", err)
	}
	// Create text representation of the private key
	marshaledKey, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return fmt.Errorf("can't marshal private key: %w", err)
	}
	keyPEMBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshaledKey,
	}
	c.PemKey = strings.TrimSpace(string(pem.EncodeToMemory(keyPEMBlock)))
	return nil
}

func (c *Certificate) PublicKey() any {
	switch k := c.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func (c *Certificate) GenerateCSR() (string, error) {
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: c.CommonName,
		},
		DNSNames: append(c.AltNames, c.CommonName),
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("can't create certificate request: %w", err)
	}
	csrPEMBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}
	csrRSAPem := strings.TrimSpace(string(pem.EncodeToMemory(csrPEMBlock)))
	return csrRSAPem, nil
}
