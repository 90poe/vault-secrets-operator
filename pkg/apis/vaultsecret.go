package apis

import (
	xov1alpha1 "github.com/90poe/vault-secrets-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VaultSecret struct {
	xov1alpha1.VaultSecret
	metav1.Object
}
