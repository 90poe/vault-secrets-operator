package vaultcertificate

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/90poe/vault-secrets-operator/pkg/utils"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/hashicorp/vault/sdk/helper/certutil"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/pkg/apis/xo/v1alpha1"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type TestCreateUpdateCertificate struct {
	Objects []runtime.Object
	Status  *xov1alpha1.VaultCertificateStatus
	Err     error
	R2Rs    map[int]utils.Responce2Req
}

func beforeEachTest(t *testing.T, prefix string, queueDepth int) (*vault.Client, net.Listener, *utils.TestDoer, *runtime.Scheme) {
	config, ln, testDoer := utils.MakeTestHTTPServer(t, queueDepth)
	client, err := vault.New(
		vault.Config(config),
		vault.Addr(config.Address, false),
		vault.Role("test"),
		vault.AuthMethod("test"),
		vault.Logger(log),
		vault.SecretsPathPrefix(prefix),
	)
	assert.NoError(t, err)
	sc := scheme.Scheme
	sc.AddKnownTypes(xov1alpha1.SchemeGroupVersion, &xov1alpha1.VaultCertificate{})
	sc.AddKnownTypes(xov1alpha1.SchemeGroupVersion, &xov1alpha1.VaultCertificateList{})
	return client, ln, testDoer, sc
}

func TestReconcile(t *testing.T) {
	var (
		name      = "test-vaultcertificate"
		namespace = "operator"
	)

	client, ln, testDoer, sc := beforeEachTest(t, "test", 1)
	defer ln.Close()
	defer testDoer.Close()
	// Create fake K8S client
	cl := fake.NewFakeClient()

	// Create ReconcileVaultCertificate
	rp := &ReconcileVaultCertificate{
		client: cl,
		scheme: sc,
		vault:  client,
		ctx:    context.TODO(),
		log:    log,
	}
	// Create mock reconcile request
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	// Call Reconcile
	res, err := rp.Reconcile(req)
	assert.NoError(t, err)
	assert.Equal(t, res.Requeue, false)
}

func TestCreateUpdate(t *testing.T) {
	var (
		name      = "test-VaultCertificates"
		namespace = "operator"
	)
	prefix := "secret/dev"
	ownerTrue := true
	_ = ownerTrue
	// Create mock reconcile request
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	now := time.Now().Unix()
	tests := []TestCreateUpdateCertificate{
		{
			//Succesfull create
			Objects: []runtime.Object{
				&xov1alpha1.VaultCertificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultCertificateSpec{
						Name: name,
						TLSCertificates: []xov1alpha1.TLSCertificate{
							{
								VaultPKIProfile: "k8s",
								CommonName:      "short-cert",
								RevokeOnDelete:  false,
								TTL:             1,
								CACertKeyName:   "ca.crt",
								CertKeyName:     "tls.crt",
								PrivateKeyName:  "tls.key",
							},
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeTLS,
					},
				},
			},
			Status: &xov1alpha1.VaultCertificateStatus{
				LastReadTime: now,
			},
			R2Rs: map[int]utils.Responce2Req{
				1: {
					RequestURI:   "/v1/sys/internal/ui/mounts/secret/vault-secrets-operator/profiles/k8s",
					ResponceCode: 200,
					Responce:     `{"request_id":"d0b59e13-62a9-20d1-1464-6204c7302034","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   "/v1/secret/vault-secrets-operator/profiles/k8s",
					ResponceCode: 200,
					Responce:     `{"request_id":"d2f0cfd1-dee8-62cd-4def-d22cec491e91","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"default_ttl":"8760","domain":"svc.cluster.local","pki_cache_path":"k8s","pki_path":"pki-k8s","pki_role":"k8s"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				3: {
					RequestURI:   "/v1/sys/internal/ui/mounts/secret/vault-secrets-operator/tls-cache/k8s/short-cert.svc.cluster.local",
					ResponceCode: 200,
					Responce:     `{"request_id":"9ae3673c-2fce-48d1-cffc-512f06f01043","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				4: {
					RequestURI:   "/v1/secret/vault-secrets-operator/tls-cache/k8s/short-cert.svc.cluster.local",
					ResponceCode: 404,
					Responce:     `{"errors":[]}`,
				},
				5: {
					RequestURI:   "/v1/pki-k8s/issue/k8s",
					ResponceCode: 200,
					Responce:     generateCertOutput(t, "short-cert.svc.cluster.local"),
				},
				6: {
					RequestURI:   "/v1/secret/vault-secrets-operator/tls-cache/k8s/short-cert.svc.cluster.local",
					ResponceCode: 404,
					Responce:     `{"errors":[]}`,
				},
				7: {
					RequestURI:   "/v1/secret/vault-secrets-operator/tls-cache/k8s/short-cert.svc.cluster.local",
					ResponceCode: 200,
					Responce:     `{"errors":[]}`,
				},
			},
		},
	}
	for _, test := range tests {
		client, ln, testDoer, sc := beforeEachTest(t, prefix, len(test.R2Rs))
		defer ln.Close()
		defer testDoer.Close()
		r2rKeys := make([]int, 0, len(test.R2Rs))
		for key := range test.R2Rs {
			r2rKeys = append(r2rKeys, key)
		}
		sort.Ints(r2rKeys)
		for _, value := range r2rKeys {
			testDoer.R2rChan <- test.R2Rs[value]
		}

		// Create fake K8S client
		cl := fake.NewFakeClient(test.Objects...)
		// Create ReconcileVaultCertificate
		rp := &ReconcileVaultCertificate{
			client: cl,
			scheme: sc,
			vault:  client,
			ctx:    context.TODO(),
			log:    log,
		}
		// Call Reconcile
		res, err := rp.Reconcile(req)
		checkLatestError := false
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			checkLatestError = true
		} else {
			assert.NoError(t, err)
			assert.Equal(t, res.Requeue, true)
		}
		foundSecret := xov1alpha1.VaultCertificate{}
		err = cl.Get(context.TODO(),
			types.NamespacedName{Name: name, Namespace: namespace},
			&foundSecret)
		assert.NoError(t, err)
		// Test LastReadTime might be within 100 seconds away from our expected time
		// as we can't predict how long test would run on circle ci
		assert.Equal(t, foundSecret.Status.LastReadTime/100,
			test.Status.LastReadTime/100)
		if checkLatestError {
			assert.Equal(t, foundSecret.Status.LatestError,
				fmt.Sprintf("%s", test.Err))
		}
	}
}

const (
	respTemplate = `
{"request_id":"c424059d-dd5f-8d59-ef87-9159dc5a1e41","lease_id":"","renewable":false,"lease_duration":0,"data":{"certificate":"%s","expiration":%d,"issuing_ca":"-----BEGIN CERTIFICATE-----\nMIIFizCCA3OgAwIBAgIUX9/3DP19298JXwf3s3t2waU4Vc0wDQYJKoZIhvcNAQEL\nBQAwTTELMAkGA1UEBhMCR0IxDjAMBgNVBAoTBTkwcG9lMQ8wDQYDVQQLEwZEZXZP\ncHMxHTAbBgNVBAMTFGNhLnN2Yy5jbHVzdGVyLmxvY2FsMB4XDTIwMDgxMjEzMjg1\nMFoXDTMwMDgxMDEzMjkxOFowTTELMAkGA1UEBhMCR0IxDjAMBgNVBAoTBTkwcG9l\nMQ8wDQYDVQQLEwZEZXZPcHMxHTAbBgNVBAMTFGNhLnN2Yy5jbHVzdGVyLmxvY2Fs\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0rC7CmC4US2E+RZ149FY\nKKs8Ok/7UHgBRw90L2QsPh6YItjbvDGhXuwkroyjAQvTLDNkp9YFt6JA238atWO2\nAJx5frvcWSilvGbipwCWrKBWx1GSAJWIr0c9YF0kSjkNpV4R8XbE6Sv7mqWmIesY\nk21/u5gHDTYeg+CFDmRFrrRYT7bkxfjrVKapyVi27BOE2VRxmV/PQ7wDzpadH1jl\nyuumHqduVRzMkvdDsxEKdAUKMhjFhdmbeVtN2GbXkpDZC2rqihbHGqlC0NMQBx3b\nfi+tdKBxT/VH+xIFJBfZtPGujqWdb/QCxVjx65zH7Oa79uFalhE1skbzXy1patYn\nDl+PxW8IXtx3vFIzqZyCpFA7gfHku1VjyiWEkPXvZbaKAob3BytfMFx2uRE4uPj9\ncCVKVazBGBe5HH/eGgLSHuA+bDjEYC8dFzcrOkQOt3HNz7VIPvSudm2BtxwC8463\n6qMv7C61bNEGPJg7ZfvnVcrPFBw3dj17JCJQ4/KH24J9+0BC6vkRdXQ1SiK2M5b9\nxXWO3bGVIkOvaGwxeunVXOSqd1fAgwHTEOFB2R4h8QhaKn6ZUYekqOiPTaq69i7m\nn5oyEQKBKtj5kaPXFKNvZ0XJihqUmEsQtUEi8KW3tZ6jrGLre1X5s8VAO4rXpmjE\npsGwCnn7r1ewYm9Eha1SqecCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud\nEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLo8C2oVnouNij3yB8KlYumRemk3MB8GA1Ud\nIwQYMBaAFLo8C2oVnouNij3yB8KlYumRemk3MA0GCSqGSIb3DQEBCwUAA4ICAQCD\nqZI8j4FmCi2SQqyfmgBGuCBqC3yWMQ0L5Bii/+hoI0KVpyH8GcT+bSZunsbEeXR6\ns0WUS/HXQRiUDT6LVZ+4xVIumKGpEUNABG5tZX3+je3Oukg+4q2yyhAoFruOqrKY\no0hl/apka2sPW4HKUwYGZIiCTYAUoVQ+JEqZMvit8Z7F2ppbKeWJSRt46yQKaKHT\nroj7Oz4XSrAmO0jXb2CWmp6Q/6gh+ENVxXRYSg2zRMaj0fpfdGzZyg3cpwzeRVUW\nfKGLha7Vb4qJ1GPvJ6qSfmiwzS0W1j2E/2+1odkYbcvy+tIRDLVQwXvQPJIrDuMS\nXLtLhzUvSwnYksqp67gYQ94Fnvck2Q2P2yGC0xHTXdHnH68GlMU6DKHUbG5NOYDp\n2JXc21ei2rfIdOrZWYglm7zKFgTK3QdOk+XwyzQ+gj67c62wHBFWYIRN3ri0ee7S\n0T52xw6OZbp9SgxWVoWMos++W4IFf/N3ZodzLenk5mr+7eG/GQpehRfWCpql1+3Y\naMT2/C8+MexxGXhGHvo6Rc8ffnlZ+H1yC/i0OsoasVSULbMhOFqPsQMUgqKkXOGS\nukmlnohnD9oveFOb752ycSskwwVlH0K6JHEU3mBehzj8rAJnXXS9XTG4b+Mwhqfl\n1B+B6uPC+Z9HbJkGMHwpwMyWu21evykSnVI0UqEAhQ==\n-----END CERTIFICATE-----","private_key":"%s","private_key_type":"rsa","serial_number":"%s"},"wrap_info":null,"warnings":null,"auth":null}
`
)

func generateCertOutput(t *testing.T, cn string) string {
	// Addopted from https://golang.org/src/crypto/tls/generate_cert.go
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(t, err, "can't generate Key: %v", err)
	keyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	notBefore := time.Now()
	notAfter := notBefore.Add(1 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	assert.NoError(t, err, "can't generate serial nr: %v", err)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Co"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err, "can't create certificate: %v", err)
	certPEM := certificates.GetPEMBundle(derBytes, "CERTIFICATE")
	privByte, err := x509.MarshalPKCS8PrivateKey(priv)
	assert.NoError(t, err, "can't marshal private key: %v", err)
	privPEM := certificates.GetPEMBundle(privByte, "PRIVATE KEY")
	return fmt.Sprintf(
		respTemplate,
		strings.ReplaceAll(string(certPEM), "\n", "\\n"),
		notAfter.Unix(),
		strings.ReplaceAll(string(privPEM), "\n", "\\n"),
		certutil.GetHexFormatted(
			serialNumber.Bytes(),
			consts.TLSSerialHumanSeparator,
		),
	)
}
