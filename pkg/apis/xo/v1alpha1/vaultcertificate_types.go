package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// TLSCertificate will hold information on how to get certificates from Vault
type TLSCertificate struct {
	// Profile in Vault which keeps PKI settings.
	// Profiles are kept in Vault at path 'secret/vault-secrets-operator/profiles/'
	// Each profile is a secret, which has data in it,
	// example: profile 'linkerd', then secret will be 'secret/vault-secrets-operator/profiles/linkerd'
	// Profile secret must have such values:
	// 1. pki_path - Path in Vault to PKI
	// 2. domain - Domain name to add to Certificate
	// 3. default_ttl - Default TTL for certs in Hours
	// 4. pki_role - Role which to use for Cert issuing
	// 5. pki_cache_path - Path to cache in Vault to store TLS certs. Need to be added to operator default Path
	// +kubebuilder:validation:MinLength=2
	VaultPKIProfile string `json:"vault_pki_profile"`
	// Prefix of CN for Certificate, domain would be taken from Profile
	// +kubebuilder:validation:MinLength=2
	CommonName string `json:"common_name"`
	// RevokeOnDelete would require to delete certificate upon deletion of CRD
	// +optional
	RevokeOnDelete bool `json:"revoke_on_delete,omitempty"`
	// Certificate TTL in hours, if not defined we would use default TTL from profile
	// +optional
	// +kubebuilder:validation:Minimum=1
	TTL int64 `json:"ttl,omitempty"`
	// Take MAX TTL which is available on PKI
	// +optional
	MaxTTL bool `json:"max_ttl,omitempty"`
	// IntermediateCA would allow to generate intermediate CA for signing other certs (example for linkerd)
	// +optional
	IntermediateCA bool `json:"intermediate_ca,omitempty"`
	// Type of private key for certificate, ec-Prime256-1 by default
	// +optional
	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:Pattern=`^(rsa2048|rsa4096|ec-Prime256-1)$`
	IntermediateCAPrivateKeyAlgorith string `json:"intermediate_ca_priv_key_alg,omitempty"`
	// CACertKeyName would set key name of CA certificate PEM in secret data.
	// Would be not set in Secret if omited.
	// +optional
	// +kubebuilder:validation:MinLength=2
	CACertKeyName string `json:"ca_cert_key_name,omitempty"`
	// CertKeyName would set key name of certificate PEM in secret data
	// +kubebuilder:validation:MinLength=2
	CertKeyName string `json:"cert_key_name"`
	// PrivateKeyName would set key name of private key PEM in secret data
	// +kubebuilder:validation:MinLength=2
	PrivateKeyName string `json:"private_key_name"`
}

// VaultCertificateSpec defines the desired state of VaultCertificate
type VaultCertificateSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html

	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[^-_+A-Z][^A-Z\\\/\*\?"\<\> ,|#]{1,254}$`
	Name string `json:"name"`
	// How offten to re-read secrets from Vault (in seconds).
	// Min 60 minutes, Max 1 year (in seconds)
	// +kubebuilder:validation:Minimum=3600
	// +kubebuilder:validation:Maximum=31536000
	ReReadIntervals int64 `json:"reread_intervals"`

	//TLSCertificates is list of TLSCertificate to be added to Secret
	// +kubebuilder:validation:MinItems=1
	TLSCertificates []TLSCertificate `json:"tls_certs"`

	// Type is the type of the Kubernetes secret, which will be created by the
	// Secrets From Vault Operator.
	Type corev1.SecretType `json:"type"`
}

// VaultCertificateStatus defines the observed state of VaultCertificate
type VaultCertificateStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html

	// Unix timestamp when secret was read last time, required for re-reading schedule.
	//  If LastReadTime < now().Seconds() - ReReadIntervals, then operator would re-read values from Vault
	LastReadTime int64 `json:"last_read_time"`
	// CertificateSerials holds certificate CN as key and serial as value
	// +optional
	CertificateSerials map[string]string `json:"cert_serials,omitempty"`
	// LatestError would hold error, if last operation was un-successful, or it would be empty otherways
	// +optional
	LatestError string `json:"latest_error,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultCertificate is the Schema for the vaultcertificates API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=vaultcertificates,scope=Namespaced
type VaultCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultCertificateSpec   `json:"spec,omitempty"`
	Status VaultCertificateStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VaultCertificateList contains a list of VaultCertificate
type VaultCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultCertificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultCertificate{}, &VaultCertificateList{})
}
