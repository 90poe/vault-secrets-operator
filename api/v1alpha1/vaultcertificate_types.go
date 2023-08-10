/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// VaultCertificateSpec defines the desired state of VaultCertificate
type VaultCertificateSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:MinLength=3
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Pattern=`^[^-_+A-Z][^A-Z\\\/\*\?"\<\> ,|#]{1,254}$`
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// Path PKI in Vault.
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Required
	VaultPKIPath string `json:"vault_pki_path"`
	// For future use of ec and ecdsa
	// +kubebuilder:default=rsa
	// +kubebuilder:validation:Pattern=`^(rsa|ec|ecdsa)$`
	KeyType string `json:"key_type,omitempty"`
	// Key length
	// +kubebuilder:default=4096
	KeyLength uint `json:"key_length,omitempty"`
	// Key ECDSA curve
	// +kubebuilder:validation:Pattern=`^(p224|p256|p384|p521)$`
	ECDSACurve string `json:"ecdsa_curve,omitempty"`
	// +kubebuilder:validation:Required
	CommonName string `json:"cn"`
	// Alternative names if you need more than one
	// CommonName will be added automatically
	AltNames []string `json:"alt_names,omitempty"`
	// What is TTL for certificate (in seconds).
	// Min 5 minutes, Max 1 year (in seconds). Default 24 hours
	//+kubebuilder:validation:Minimum=300
	//+kubebuilder:validation:Maximum=31536000
	//+kubebuilder:default=86400
	CertTTL int `json:"cert_ttl,omitempty"`
	// Type is the type of the Kubernetes secret, which will be created by the
	// Type of secret. Default kubernetes.io/tls
	//+kubebuilder:default=kubernetes.io/tls
	Type corev1.SecretType `json:"type,omitempty"`
}

// VaultCertificateStatus defines the observed state of VaultCertificate
type VaultCertificateStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Conditions store the status conditions of the Memcached instances
	// +operator-sdk:csv:customresourcedefinitions:type=status
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type" protobuf:"bytes,1,rep,name=conditions"`
	// Cert expire date
	CertValidUntil metav1.Time `json:"cert_valid_until,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// VaultCertificate is the Schema for the vaultcertificates API
type VaultCertificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultCertificateSpec   `json:"spec,omitempty"`
	Status VaultCertificateStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// VaultCertificateList contains a list of VaultCertificate
type VaultCertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultCertificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&VaultCertificate{}, &VaultCertificateList{})
}
