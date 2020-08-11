package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultSecretSpec defines the desired state of VaultSecret
type VaultSecretSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html

	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[^-_+A-Z][^A-Z\\\/\*\?"\<\> ,|#]{1,254}$`
	Name string `json:"name"`
	// Path is map of secrets and their path in Vault. Keys would be ported to
	// secrets and values would be taken from Vault secrets values.
	// NOTE: 'value' keys in Vault would be base64 encoded for K8S secrets and
	//       'base64_values' keys in Vault would not be encoded for K8S secrets
	SecretsPaths map[string]string `json:"secrets_paths"`
	// ProvidedSecrets are secrets, which we don't need to look for in Vault,
	//  but take from this structure and push to final secret verbatim.
	//  Required for mixed secrets, where part is from Vault, part is provided in CRD.
	ProvidedSecrets map[string]string `json:"provided_secrets,omitempty"`
	// How offten to re-read secrets from Vault (in seconds).
	// Min 5 minutes, Max 1 year (in seconds)
	// +kubebuilder:validation:Minimum=300
	// +kubebuilder:validation:Maximum=31536000
	ReReadIntervals int64 `json:"reread_intervals"`
	// Type is the type of the Kubernetes secret, which will be created by the
	// VaultSecrets Operator.
	Type corev1.SecretType `json:"type"`
}

// VaultSecretStatus defines the observed state of VaultSecret
type VaultSecretStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	// Unix timestamp when secret was read last time, required for re-reading schedule.
	//  If LastReadTime < now().Seconds() - ReReadIntervals, then operator would re-read values from Vault
	LastReadTime int64 `json:"last_read_time"`
	// LatestError would hold error, if last operation was un-successful, or it would be empty otherways
	// +optional
	LatestError string `json:"latest_error,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultSecret is the Schema for the vaultsecrets API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=vaultsecrets,scope=Namespaced
type VaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSecretSpec   `json:"spec,omitempty"`
	Status VaultSecretStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultSecretList contains a list of VaultSecret
type VaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultSecret{}, &VaultSecretList{})
}
