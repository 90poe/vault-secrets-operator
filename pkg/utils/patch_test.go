package utils

import (
	"context"
	"testing"
	"time"

	xov1alpha1 "github.com/90poe/vault-secrets-operator/pkg/apis/xo/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	name      string = "test-es"
	namespace string = "operator"
)

var vaultSecret *xov1alpha1.VaultSecret = &xov1alpha1.VaultSecret{
	ObjectMeta: metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
	},
	Spec: xov1alpha1.VaultSecretSpec{
		Name: name,
	},
}
var objs []runtime.Object = []runtime.Object{vaultSecret}

func TestPatchUtilShouldPatchIfThereIsDifference(t *testing.T) {
	// Create modified postgres
	modvaultSecret := vaultSecret.DeepCopy()
	modvaultSecret.Spec.Name = "Test"
	modvaultSecret.Status.LastReadTime = time.Now().Unix()

	// Create runtime scheme
	s := scheme.Scheme
	s.AddKnownTypes(xov1alpha1.SchemeGroupVersion, &xov1alpha1.VaultSecret{})

	// Create fake client to mock API calls
	cl := fake.NewFakeClient(objs...)

	// Patch object
	err := Patch(context.TODO(), cl, vaultSecret, modvaultSecret)
	if err != nil {
		t.Fatalf("could not patch object: (%v)", err)
	}

	// Check if vaultSecret is identical to modified object
	foundvaultSecret := &xov1alpha1.VaultSecret{}
	err = cl.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace},
		foundvaultSecret)
	if err != nil {
		t.Fatalf("could not get secret from vault: (%v)", err)
	}
	// Comparison
	if foundvaultSecret.Spec.Name != modvaultSecret.Spec.Name {
		t.Fatalf("found vaultSecret is not identical to modified vaultSecret: Name == %s, expected %s",
			foundvaultSecret.Spec.Name, modvaultSecret.Spec.Name)
	}
	if foundvaultSecret.Status.LastReadTime != modvaultSecret.Status.LastReadTime {
		t.Fatalf("found vaultSecret is not identical to modified vaultSecret: LastReadTime == %v, expected %v",
			foundvaultSecret.Status.LastReadTime, modvaultSecret.Status.LastReadTime)
	}
}
