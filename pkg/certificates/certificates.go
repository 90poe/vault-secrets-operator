package certificates

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/helper/certutil"
)

//Certificate is representation of x509.Certificate
type Certificate struct {
	Serial     string
	CommonName string
	Issuer     string
	ValidFrom  time.Time
	ValidUntil time.Time
	Revoked    bool
}

//NewCertificate would convert x509 Certificate to Certificate
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

//GetRawCertificate would return certificate from string
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

//IsCertificateInRevokedList would check if cert is in revoked certificates list
func IsCertificateInRevokedList(cert *x509.Certificate, crl *pkix.CertificateList) bool {
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if cert.SerialNumber.Cmp(revokedCert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

//IsCertificateValid would verify if:
// 1. Certificate is not expired
// 2. Certificate is not in revokation list
// It would return true and certificate CN
func IsCertificateValid(pem string, crl *pkix.CertificateList) (bool, string, error) {
	rawCert, err := GetRawCertificate(pem)
	if err != nil {
		return false, "", err
	}
	revoked := IsCertificateInRevokedList(rawCert, crl)
	if revoked {
		return false, "", nil
	}
	certInfo := NewCertificate(rawCert, revoked)

	now := time.Now()
	if now.Before(certInfo.ValidFrom) || now.After(certInfo.ValidUntil) {
		//Certificate is either expired or not yet valid
		return false, "", nil
	}
	return true, certInfo.CommonName, nil
}

// GetPEMBundle would return PEM encoded PKI object of certType
func GetPEMBundle(der []byte, certType string) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  certType,
			Bytes: der,
		},
	)
}
