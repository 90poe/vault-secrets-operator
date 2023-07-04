package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
)

func SignCSR(csr []byte, notAfterStr string) (*certutil.ParsedCertBundle, error) {
	ca, err := generateCA()
	if err != nil {
		return nil, err
	}
	// Prepare CA bundle
	caInfoBundle := &certutil.CAInfoBundle{}
	caInfoBundle.PrivateKeyFormat = ca.PrivateKeyFormat
	caInfoBundle.PrivateKeyBytes = ca.PrivateKeyBytes
	caInfoBundle.PrivateKey = ca.PrivateKey
	caInfoBundle.CertificateBytes = ca.CertificateBytes
	caInfoBundle.Certificate = ca.Certificate
	caInfoBundle.CAChain = ca.CAChain
	caInfoBundle.URLs = &certutil.URLEntries{
		OCSPServers: []string{"http://localhost:8200/v1/pki-mqtt/ocsp"},
	}
	// Prepare CSR bundle
	block, _ := pem.Decode(csr)
	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	notAfter, err := time.Parse("2006-01-02T15:04:05Z", notAfterStr)
	if err != nil {
		return nil, err
	}

	cert, err := certutil.SignCertificate(&certutil.CreationBundle{
		Params: &certutil.CreationParameters{
			URLs: &certutil.URLEntries{
				IssuingCertificates:   []string{"http://localhost:8200/v1/pki-mqtt/ca"},
				CRLDistributionPoints: []string{"http://localhost:8200/v1/pki-mqtt/crl"},
			},
			NotAfter:     notAfter,
			UseCSRValues: true,
		},
		SigningBundle: caInfoBundle,
		CSR:           csrParsed,
	})
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func generateCA() (*certutil.ParsedCertBundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	subjKeyID, err := certutil.GetSubjKeyID(caKey)
	if err != nil {
		return nil, err
	}
	caCertTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "root.localhost",
		},
		SubjectKeyId:          subjKeyID,
		DNSNames:              []string{"root.localhost"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SerialNumber:          big.NewInt(mathrand.Int63()), // nolint
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(262980 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caCertTemplate, caCertTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}
	caCertPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}
	caCertPEM := strings.TrimSpace(string(pem.EncodeToMemory(caCertPEMBlock)))
	// privRSA8KeyPem := strings.TrimSpace(string(pem.EncodeToMemory(keyPEMBlock)))
	return &certutil.ParsedCertBundle{
		PrivateKey:       caKey,
		Certificate:      caCert,
		CertificateBytes: []byte(caCertPEM),
	}, nil
}

// Func should be used if we are going to issue cert not sign
func GenCertSelfSigned(cn, validTill string) (*certutil.CertBundle, *x509.RevocationList, error) {
	// Taken from
	// https://github.com/golang/go/blob/master/src/crypto/tls/generate_cert.go
	// https://github.com/hashicorp/vault/blob/sdk/v0.9.1/sdk/helper/certutil/certutil_test.go
	// Generate CA key
	ca, err := generateCA()
	if err != nil {
		return nil, nil, err
	}
	caBundle, err := ca.ToCertBundle()
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	var notAfter time.Time
	if len(validTill) == 0 {
		notAfter = time.Now().Add(1 * time.Hour) // Add one our from now
	} else {
		notAfter, err = time.Parse("2006-01-02T15:04:05Z", validTill)
		if err != nil {
			return nil, nil, err
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	subjKeyID, err := certutil.GetSubjKeyID(key)
	if err != nil {
		return nil, nil, err
	}
	certTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SubjectKeyId: subjKeyID,
		DNSNames:     []string{cn},
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		SerialNumber: big.NewInt(mathrand.Int63()), // nolint
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	// Create cert for output
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, ca.Certificate, key.Public(), ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	certPEMBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	certRSAPem := strings.TrimSpace(string(pem.EncodeToMemory(certPEMBlock)))
	marshaledKey := x509.MarshalPKCS1PrivateKey(key)
	keyPEMBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: marshaledKey,
	}
	privRSAKeyPem := strings.TrimSpace(string(pem.EncodeToMemory(keyPEMBlock)))
	// Create CRL
	crlBytes, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:     big.NewInt(5),
		ThisUpdate: time.Time{}.Add(time.Hour * 24),
		NextUpdate: time.Time{}.Add(time.Hour * 48),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   certTemplate.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}, ca.Certificate, ca.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, nil, err
	}
	// final cert bundle
	certBundle := certutil.CertBundle{
		Certificate: certRSAPem,
		IssuingCA:   caBundle.Certificate,
		PrivateKey:  privRSAKeyPem,
	}

	return &certBundle, crl, nil
}
