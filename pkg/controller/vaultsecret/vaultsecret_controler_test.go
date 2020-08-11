package vaultsecret

import (
	"context"
	"fmt"
	"net"
	"path"
	"sort"
	"testing"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/vault"

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

type TestCreateUpdateSecret struct {
	Objects []runtime.Object
	Status  *xov1alpha1.VaultSecretStatus
	Err     error
	R2Rs    map[int]Responce2Req
}

func beforeEachTest(t *testing.T, prefix string) (*vault.Client, net.Listener, *TestDoer, *runtime.Scheme) {
	config, ln, testDoer := testHTTPServer(t)
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
	sc.AddKnownTypes(xov1alpha1.SchemeGroupVersion, &xov1alpha1.VaultSecret{})
	sc.AddKnownTypes(xov1alpha1.SchemeGroupVersion, &xov1alpha1.VaultSecretList{})
	return client, ln, testDoer, sc
}

func TestReconcile(t *testing.T) {
	var (
		name      = "test-vaultsecret"
		namespace = "operator"
	)

	client, ln, testDoer, sc := beforeEachTest(t, "test")
	defer ln.Close()
	defer testDoer.Close()
	// Create fake K8S client
	cl := fake.NewFakeClient()

	// Create ReconcileVaultSecret
	rp := &ReconcileVaultSecret{
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
		name      = "test-vaultsecrets"
		namespace = "operator"
	)
	secretPath := "shared/test_url"
	prefix := "secret/dev"
	ownerTrue := true
	// Create mock reconcile request
	req := reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      name,
			Namespace: namespace,
		},
	}
	now := time.Now().Unix()
	tests := []TestCreateUpdateSecret{
		{
			//Succesfull create
			Objects: []runtime.Object{
				&xov1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultSecretSpec{
						Name: name,
						SecretsPaths: map[string]string{
							"test": secretPath,
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeOpaque,
					},
				},
			},
			Status: &xov1alpha1.VaultSecretStatus{
				LastReadTime: now,
			},
			R2Rs: map[int]Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "204609fa-02b4-e56f-803c-119c0fef255f",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 0,
						"data": {
							"accessor": "kv_ab99964e",
							"config": {
								"default_lease_ttl": 0,
								"force_no_cache": false,
								"max_lease_ttl": 0
							},
							"description": "key/value secret storage",
							"external_entropy_access": false,
							"local": false,
							"options": {
								"version": "1"
							},
							"path": "secret/",
							"seal_wrap": false,
							"type": "kv",
							"uuid": "c7415bec-f301-0c14-2c48-6d17d549aba1"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "ba0f8d29-262b-db3a-3660-746f593c97a7",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 2764800,
						"data": {
							"value": "https://sss/10"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
			},
		},
		{
			//Unsuccesfull create - secret not found
			Objects: []runtime.Object{
				&xov1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultSecretSpec{
						Name: name,
						SecretsPaths: map[string]string{
							"test": secretPath,
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeOpaque,
					},
				},
			},
			Status: &xov1alpha1.VaultSecretStatus{
				LastReadTime: 0,
			},
			Err: fmt.Errorf("can't make new Secret: no such secret at path '%s'",
				path.Join(prefix, secretPath)),
			R2Rs: map[int]Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "204609fa-02b4-e56f-803c-119c0fef255f",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 0,
						"data": {
							"accessor": "kv_ab99964e",
							"config": {
								"default_lease_ttl": 0,
								"force_no_cache": false,
								"max_lease_ttl": 0
							},
							"description": "key/value secret storage",
							"external_entropy_access": false,
							"local": false,
							"options": {
								"version": "1"
							},
							"path": "secret/",
							"seal_wrap": false,
							"type": "kv",
							"uuid": "c7415bec-f301-0c14-2c48-6d17d549aba1"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 404,
					Responce:     `{"errors":[]}`,
				},
			},
		},
		{
			//Succesfull update
			Objects: []runtime.Object{
				&xov1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultSecretSpec{
						Name: name,
						SecretsPaths: map[string]string{
							"test": secretPath,
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeOpaque,
					},
					Status: xov1alpha1.VaultSecretStatus{
						LastReadTime: now,
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "xo.90poe.io/v1alpha1",
								BlockOwnerDeletion: &ownerTrue,
								Controller:         &ownerTrue,
								Kind:               "VaultSecret",
								Name:               name,
								UID:                "47efab25-ded1-45e1-8337-27b64ee7a9f6",
							},
						},
					},
					Data: map[string][]byte{
						"test1": []byte("BASE64ENCODED"),
					},
					Type: corev1.SecretTypeOpaque,
				},
			},
			Status: &xov1alpha1.VaultSecretStatus{
				LastReadTime: now,
			},
			R2Rs: map[int]Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "204609fa-02b4-e56f-803c-119c0fef255f",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 0,
						"data": {
							"accessor": "kv_ab99964e",
							"config": {
								"default_lease_ttl": 0,
								"force_no_cache": false,
								"max_lease_ttl": 0
							},
							"description": "key/value secret storage",
							"external_entropy_access": false,
							"local": false,
							"options": {
								"version": "1"
							},
							"path": "secret/",
							"seal_wrap": false,
							"type": "kv",
							"uuid": "c7415bec-f301-0c14-2c48-6d17d549aba1"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "ba0f8d29-262b-db3a-3660-746f593c97a7",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 2764800,
						"data": {
							"value": "https://sss/10"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
			},
		},
		{
			//Update not required
			Objects: []runtime.Object{
				&xov1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultSecretSpec{
						Name: name,
						SecretsPaths: map[string]string{
							"test": secretPath,
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeOpaque,
					},
					Status: xov1alpha1.VaultSecretStatus{
						LastReadTime: now,
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "xo.90poe.io/v1alpha1",
								BlockOwnerDeletion: &ownerTrue,
								Controller:         &ownerTrue,
								Kind:               "VaultSecret",
								Name:               name,
								UID:                "47efab25-ded1-45e1-8337-27b64ee7a9f6",
							},
						},
					},
					Data: map[string][]byte{
						"test": []byte("https://sss/10"),
					},
					Type: corev1.SecretTypeOpaque,
				},
			},
			Status: &xov1alpha1.VaultSecretStatus{
				LastReadTime: now,
			},
			R2Rs: map[int]Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "204609fa-02b4-e56f-803c-119c0fef255f",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 0,
						"data": {
							"accessor": "kv_ab99964e",
							"config": {
								"default_lease_ttl": 0,
								"force_no_cache": false,
								"max_lease_ttl": 0
							},
							"description": "key/value secret storage",
							"external_entropy_access": false,
							"local": false,
							"options": {
								"version": "1"
							},
							"path": "secret/",
							"seal_wrap": false,
							"type": "kv",
							"uuid": "c7415bec-f301-0c14-2c48-6d17d549aba1"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "ba0f8d29-262b-db3a-3660-746f593c97a7",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 2764800,
						"data": {
							"value": "https://sss/10"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
			},
		},
		{
			//Delete
			Objects: []runtime.Object{
				&xov1alpha1.VaultSecret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
					},
					Spec: xov1alpha1.VaultSecretSpec{
						Name: name,
						SecretsPaths: map[string]string{
							"test": secretPath,
						},
						ReReadIntervals: 300,
						Type:            corev1.SecretTypeOpaque,
					},
					Status: xov1alpha1.VaultSecretStatus{
						LastReadTime: now,
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      name,
						Namespace: namespace,
						OwnerReferences: []metav1.OwnerReference{
							{
								APIVersion:         "xo.90poe.io/v1alpha1",
								BlockOwnerDeletion: &ownerTrue,
								Controller:         &ownerTrue,
								Kind:               "VaultSecret",
								Name:               name,
								UID:                "47efab25-ded1-45e1-8337-27b64ee7a9f6",
							},
						},
					},
					Data: map[string][]byte{
						"test": []byte("https://sss/10"),
					},
					Type: corev1.SecretTypeDockerConfigJson,
				},
			},
			Status: &xov1alpha1.VaultSecretStatus{
				LastReadTime: now,
			},
			R2Rs: map[int]Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "204609fa-02b4-e56f-803c-119c0fef255f",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 0,
						"data": {
							"accessor": "kv_ab99964e",
							"config": {
								"default_lease_ttl": 0,
								"force_no_cache": false,
								"max_lease_ttl": 0
							},
							"description": "key/value secret storage",
							"external_entropy_access": false,
							"local": false,
							"options": {
								"version": "1"
							},
							"path": "secret/",
							"seal_wrap": false,
							"type": "kv",
							"uuid": "c7415bec-f301-0c14-2c48-6d17d549aba1"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					Responce: `{
						"request_id": "ba0f8d29-262b-db3a-3660-746f593c97a7",
						"lease_id": "",
						"renewable": false,
						"lease_duration": 2764800,
						"data": {
							"value": "https://sss/10"
						},
						"wrap_info": null,
						"warnings": null,
						"auth": null
					}`,
				},
			},
		},
	}
	for _, test := range tests {
		client, ln, testDoer, sc := beforeEachTest(t, prefix)
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
		// Create ReconcileVaultSecret
		rp := &ReconcileVaultSecret{
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
		foundSecret := xov1alpha1.VaultSecret{}
		err = cl.Get(context.TODO(),
			types.NamespacedName{Name: name, Namespace: namespace},
			&foundSecret)
		assert.NoError(t, err)
		// Test LastReadTime might be within 10 seconds away from our expected time
		// as we can't predict how long test would run
		assert.Equal(t, foundSecret.Status.LastReadTime/10,
			test.Status.LastReadTime/10)
		if checkLatestError {
			assert.Equal(t, foundSecret.Status.LatestError,
				fmt.Sprintf("%s", test.Err))
		}
	}
}
