package utils

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var (
	name      string = "test-es"
	namespace string = "default"

	vaultSecret *xov1alpha1.VaultSecret = &xov1alpha1.VaultSecret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: xov1alpha1.VaultSecretSpec{
			Name: name,
			SecretsPaths: map[string]string{
				"some": "test",
			},
		},
	}
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
)

func TestUTILSs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Utilities Suite")
}

var _ = Describe("Utils", func() {
	It("can patch VaultSecret", func() {
		// Create modified object
		modvaultSecret := vaultSecret.DeepCopy()
		modvaultSecret.Spec.Name = "test"
		modvaultSecret.Status.LastReadTime = time.Now().Unix()

		// Patch object
		err := PatchVaultSecret(context.TODO(), k8sClient, vaultSecret, modvaultSecret)
		Expect(err).NotTo(HaveOccurred())

		// Check if vaultSecret is identical to modified object
		foundvaultSecret := &xov1alpha1.VaultSecret{}
		err = k8sClient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace},
			foundvaultSecret)
		Expect(err).NotTo(HaveOccurred())
		// Comparison
		Expect(foundvaultSecret.Spec.Name).To(BeEquivalentTo(modvaultSecret.Spec.Name))
		Expect(foundvaultSecret.Status.LastReadTime).To(BeEquivalentTo(modvaultSecret.Status.LastReadTime))
	})
})

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("../..", "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	// cfg is defined in this file globally.
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = xov1alpha1.AddToScheme(scheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	err = k8sClient.Create(context.TODO(), vaultSecret)
	Expect(err).NotTo(HaveOccurred())
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})
