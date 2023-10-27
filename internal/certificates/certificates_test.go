package certificates_test

import (
	"testing"
	"time"

	"github.com/90poe/vault-secrets-operator/internal/certificates"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestCertificates struct {
	KeyType    string
	ECDSACurve string
	CN         string
	AltNames   []string
	KeyBits    int
	Err        string
}

func TestNewCertificates(t *testing.T) {
	t.Parallel()
	tests := []TestCertificates{
		{
			KeyType: certificates.CertificateRSA,
			KeyBits: 3092,
		},
		{
			KeyType: certificates.CertificateRSA,
			KeyBits: 0,
			Err:     "must not be 0",
		},
		{
			KeyType: "",
			KeyBits: 3092,
			Err:     "unkown certificate type ''",
		},
	}
	for _, test := range tests {
		cert, err := certificates.New(
			"", test.KeyType, test.KeyBits)
		if test.Err != "" {
			require.ErrorContains(t, err, test.Err)
			continue
		}
		require.NoError(t, err)
		assert.NotNil(t, cert)
	}
}

// write new test for each type of certificate
func TestNewPrivateKey(t *testing.T) {
	t.Parallel()
	tests := []TestCertificates{
		{
			KeyType: certificates.CertificateRSA,
			KeyBits: 2048,
		},
		{
			KeyType:    certificates.CertificateECDSA,
			KeyBits:    224,
			ECDSACurve: "P224",
		},
		{
			KeyType: certificates.CertificateEC,
			KeyBits: 256,
		},
	}
	for _, test := range tests {
		cert, err := certificates.New(
			"", test.KeyType, test.KeyBits,
			certificates.ECDSACurve(test.ECDSACurve))
		require.NoError(t, err)
		assert.NotNil(t, cert)
		err = cert.GeneratePrivateKey()
		if test.Err != "" {
			require.ErrorContains(t, err, test.Err)
			continue
		}
		require.NoError(t, err)
		keySize := certutil.GetPublicKeySize(cert.PublicKey())
		assert.Equal(t, test.KeyBits, keySize)
	}
}

func TestNewCSR(t *testing.T) {
	t.Parallel()
	tests := []TestCertificates{
		{
			KeyType: certificates.CertificateRSA,
			KeyBits: 2048,
			CN:      "test.com",
			AltNames: []string{
				"test.com",
				"*.test.com",
			},
		},
	}
	for _, test := range tests {
		cert, err := certificates.New(
			test.CN,
			test.KeyType,
			test.KeyBits)
		require.NoError(t, err)
		assert.NotNil(t, cert)
		err = cert.GeneratePrivateKey()
		require.NoError(t, err)
		csr, err := cert.GenerateCSR()
		require.NoError(t, err)
		assert.NotEmpty(t, csr)
	}
}

func TestGetCertificateFromPem(t *testing.T) {
	t.Parallel()
	// Good with CRL
	cert, crl, err := certificates.GenCertSelfSigned("some.test.com", time.Now().Add(1*time.Hour).UTC().Format("2006-01-02T15:04:05Z"))
	require.NoError(t, err)
	// good with CRL
	tlsCert, err := certificates.GetCertificateFromPem(cert.Certificate, cert.PrivateKey, cert.IssuingCA, crl)
	var errInvalid *certificates.CertificateInvalid
	assert.ErrorAs(t, err, &errInvalid)
	assert.Empty(t, tlsCert)
	// good without CRL
	tlsCert, err = certificates.GetCertificateFromPem(cert.Certificate, cert.PrivateKey, cert.IssuingCA, nil)
	assert.NoError(t, err)
	assert.Equal(t, tlsCert.PemCert, cert.Certificate)
	assert.Equal(t, tlsCert.PemKey, cert.PrivateKey)
}
