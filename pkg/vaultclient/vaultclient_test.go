package vaultclient_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/certificates"
	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/90poe/vault-secrets-operator/pkg/mocks/vault"
	"github.com/90poe/vault-secrets-operator/pkg/vaultclient"
	hvault "github.com/hashicorp/vault/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	vaultClient     *vaultclient.Client
	mockVaultClient *vault.MockClient
	err             error
	mockCtrl        *gomock.Controller
	logTest         = logf.Log.WithName("testing")
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Vault Client Suite")
}

var _ = Describe("VaultClient", func() {
	It("can get secret", func() {
		mockVaultClient.EXPECT().Read(gomock.Eq("some")).DoAndReturn(func(_ string) (*hvault.Secret, error) {
			time.Sleep(10 * time.Millisecond)
			return &hvault.Secret{
				RequestID:     "ba0f8d29-262b-db3a-3660-746f593c97a7",
				LeaseID:       "",
				LeaseDuration: 2764800,
				Data: map[string]interface{}{
					"value": "secret",
				},
			}, nil
		})
		sec, _, err := vaultClient.GetSecret("some")
		Expect(err).To(BeNil())
		Expect(sec).To(BeEquivalentTo("secret"))
	})
	It("can not get secret", func() {
		mockVaultClient.EXPECT().Read(gomock.Eq("some")).DoAndReturn(func(_ string) (*hvault.Secret, error) {
			time.Sleep(1 * time.Second)
			return nil, fmt.Errorf("can't get secret from path 'some': no such secret at path 'some'")
		})
		sec, _, err := vaultClient.GetSecret("some")
		Expect(err).To(MatchError(fmt.Errorf("can't get secret from path 'some': no such secret at path 'some'")))
		Expect(sec).To(BeEmpty())
	})
	// certificate part
	It("can sign certificate", func() {
		validUntil := time.Now().Add(24 * time.Hour)
		testCert, err := certificates.New(
			CNname, "rsa", 2048,
			certificates.ValidUntil(validUntil),
			certificates.AltNames([]string{"*.zodiac.iot.drydock.studio", CNname}),
		)
		Expect(err).To(BeNil())
		err = testCert.GeneratePrivateKey()
		Expect(err).To(BeNil())
		mockVaultClient.EXPECT().Write(
			gomock.Eq("/pki-mqtt/sign/vpn"), gomock.Any(),
		).DoAndReturn(func(_ string, data map[string]interface{}) (*hvault.Secret, error) {
			csr, ok := data["csr"].(string)
			Expect(ok).To(BeTrue())
			notAfter, ok := data["not_after"].(string)
			Expect(ok).To(BeTrue())
			cert, err := certificates.SignCSR([]byte(csr), notAfter)
			Expect(err).To(BeNil())
			certBundle, err := cert.ToCertBundle()
			Expect(err).To(BeNil())
			return &hvault.Secret{
				RequestID:     "ba0f8d29-262b-db3a-3660-746f593c97a7",
				LeaseID:       "",
				LeaseDuration: 2764800,
				Data: map[string]interface{}{
					"certificate": certBundle.Certificate,
					"issuing_ca":  certBundle.CAChain[0],
				},
			}, nil
		})
		testCert, err = vaultClient.GetSignedCertificate("pki-mqtt", "vpn", testCert)
		Expect(err).To(BeNil())
		parsedCert, err := certificates.GetRawCertificate(testCert.PemCert)
		Expect(err).To(BeNil())
		Expect(parsedCert.Subject.CommonName).To(Equal(CNname))
	})
	It("get certificate from cache", func() {
		var (
			CN      = "some.test.com"
			pkiPath = "pki-mqtt"
		)
		mockVaultClient.EXPECT().Read(
			gomock.Eq(fmt.Sprintf("/v1/%s/%s/test.com/some", consts.CertCachePath, pkiPath)),
		).DoAndReturn(func(_ string) (*hvault.Secret, error) {
			validUntil := time.Now().Add(24 * time.Hour)
			cert, _, err := certificates.GenCertSelfSigned(CN, validUntil.UTC().Format("2006-01-02T15:04:05Z"))
			Expect(err).To(BeNil())
			return &hvault.Secret{
				RequestID:     "ba0f8d29-262b-db3a-3660-746f593c97a7",
				LeaseID:       "",
				LeaseDuration: 2764800,
				Data: map[string]interface{}{
					"certificate": cert.Certificate,
					"issuing_ca":  cert.IssuingCA,
					"private_key": cert.PrivateKey,
				},
			}, nil
		})
		cert, key, CA, err := vaultClient.GetCertFromCache(pkiPath, CN)
		Expect(err).To(BeNil())
		Expect(cert).To(Not(BeEmpty()))
		Expect(key).To(Not(BeEmpty()))
		Expect(CA).To(Not(BeEmpty()))
	})
	It("can't get certificate from cache", func() {
		var (
			CN      = "some.test.com"
			pkiPath = "pki-mqtt"
		)
		mockVaultClient.EXPECT().Read(
			gomock.Eq(fmt.Sprintf("/v1/%s/%s/test.com/some", consts.CertCachePath, pkiPath)),
		).DoAndReturn(func(_ string) (*hvault.Secret, error) {
			return nil, fmt.Errorf("not found")
		})
		cert, key, CA, err := vaultClient.GetCertFromCache(pkiPath, CN)
		Expect(err).To(Not(BeNil()))
		Expect(cert).To(BeEmpty())
		Expect(key).To(BeEmpty())
		Expect(CA).To(BeEmpty())
	})
})

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))
	mockCtrl = gomock.NewController(GinkgoT())

	By("make vault mock")
	mockVaultClient = vault.NewMockClient(mockCtrl)
	ctx, cancelfn := context.WithCancel(context.TODO())
	vaultClient, err = vaultclient.New(
		vaultclient.VaultClient(mockVaultClient),
		vaultclient.Logger(logTest),
		vaultclient.ContextWithCancelFN(ctx, cancelfn),
	)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	mockCtrl.Finish()
})
