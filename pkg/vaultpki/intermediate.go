package vaultpki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"strings"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/pkg/apis/xo/v1alpha1"
	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
)

func (t *TLSCert) generateIntermediatePEM(tlsReq *xov1alpha1.TLSCertificate) error {
	// 1. Lets get root CA, we need to copy a lot from it
	caPEM, err := t.getCA()
	if err != nil {
		return err
	}
	privKey, err := t.generatePrivateKey(tlsReq)
	if err != nil {
		return fmt.Errorf("can't generate private key: %w", err)
	}
	intSubject := caPEM.Subject
	cnParts := strings.Split(caPEM.Subject.CommonName, ".")
	if len(cnParts) == 1 {
		// We make at least slice with 2 parts
		cnParts = append(cnParts, cnParts[0])
	}
	cnParts[0] = tlsReq.CommonName
	intSubject.CommonName = strings.Join(cnParts, ".")
	intTemplate := x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Subject:            intSubject,
		DNSNames:           caPEM.DNSNames,
		EmailAddresses:     caPEM.EmailAddresses,
		IPAddresses:        caPEM.IPAddresses,
		URIs:               caPEM.URIs,
		ExtraExtensions:    caPEM.ExtraExtensions,
	}
	// Get CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &intTemplate, privKey)
	if err != nil {
		return err
	}
	// Make PEM bundle from CSR with CERTIFICATE REQUEST
	csrPEM := certificates.GetPEMBundle(csr, "CERTIFICATE REQUEST")
	// Prepare data for Intermediate signing
	data := make(map[string]interface{})
	data["csr"] = string(csrPEM)
	data["format"] = "pem_bundle"
	certTTL := uint(tlsReq.TTL)
	if tlsReq.MaxTTL {
		certTTL, err = t.getMaxTTL()
		if err != nil {
			return fmt.Errorf("requesting max TTL: %w", err)
		}
	}
	data["ttl"] = fmt.Sprintf("%dh", certTTL)
	// Request Vault to sign Intermediate
	logical := t.client.Logical()
	secret, err := logical.Write(fmt.Sprintf("%s/root/sign-intermediate",
		t.pkiPath), data)
	if err != nil {
		return fmt.Errorf("requesting csr signing: %w", err)
	}
	// Marshal Private Key
	var privByte []byte
	if tlsReq.IntermediateCAPrivateKeyAlgorith == consts.PKIKeyAlgECPrime256 {
		privByte, err = x509.MarshalECPrivateKey(privKey.(*ecdsa.PrivateKey))
	} else {
		privByte, err = x509.MarshalPKCS8PrivateKey(privKey)
	}
	if err != nil {
		return err
	}
	privPEM := certificates.GetPEMBundle(privByte, t.getPrivateKeyString(tlsReq))
	t.PrivateKey = string(privPEM)
	cert, _, ca, err := t.parseCertValuesFromSecret(secret)
	if err != nil {
		return fmt.Errorf("can't read generated secret: %w", err)
	}
	t.Certificate = cert
	t.IssuingCACertificate = ca
	return nil
}

func (t *TLSCert) getPrivateKeyString(tlsReq *xov1alpha1.TLSCertificate) string {
	ret := "PRIVATE KEY"

	if tlsReq.IntermediateCAPrivateKeyAlgorith == consts.PKIKeyAlgECPrime256 {
		ret = "EC PRIVATE KEY"
	}
	return ret
}
