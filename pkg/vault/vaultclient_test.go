package vault_test

import (
	"fmt"
	"path"
	"sort"
	"testing"

	"github.com/90poe/vault-secrets-operator/pkg/testhelpers"
	"github.com/90poe/vault-secrets-operator/pkg/vault"
	"github.com/stretchr/testify/assert"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var log = logf.Log.WithName("testing")

type TestSecretFromVault struct {
	R2R               map[int]testhelpers.Responce2Req
	Err               error
	Secret            string
	IsBase64          bool
	AdditionalOptions []vault.Option
}

type TestSecretFromVaultNew struct {
	Err     error
	Options []vault.Option
}

func TestNew(t *testing.T) {
	config, ln, testDoer, err := testhelpers.HTTPServerWithAPI()
	assert.NoError(t, err)
	defer ln.Close()
	defer testDoer.Close()
	tests := []TestSecretFromVaultNew{
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Addr(config.Address, false),
				vault.Role("test"),
				vault.AuthMethod("test"),
				vault.Logger(log),
			},
		},
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Addr("config.Address", false),
				vault.Role("test"),
				vault.AuthMethod("test"),
				vault.Logger(log),
			},
			Err: fmt.Errorf("can't make new Vault Client: invalid Vault URL address"),
		},
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Addr(config.Address, false),
				vault.Logger(log),
			},
			Err: fmt.Errorf("can't use empty Vault role"),
		},
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Role("test"),
				vault.Logger(log),
			},
			Err: fmt.Errorf("can't use empty Vault address"),
		},
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Addr("  ", false),
				vault.Role("test"),
				vault.Logger(log),
			},
			Err: fmt.Errorf("can't make new Vault Client: address for Vault can't be empty"),
		},
		{
			Options: []vault.Option{
				vault.Config(config),
				vault.Addr(config.Address, false),
				vault.Role("test"),
			},
			Err: fmt.Errorf("can't use empty logger"),
		},
	}
	for _, test := range tests {
		client, err := vault.New(test.Options...)
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			continue
		}
		assert.NoError(t, err)
		assert.NotNil(t, client, "vault should not be nil")
	}
}

func TestGetSecretWithPrefix(t *testing.T) {
	config, ln, testDoer, err := testhelpers.HTTPServerWithAPI()
	assert.NoError(t, err)
	defer ln.Close()
	defer testDoer.Close()
	//nolint
	secretPath := "shared/test_url"
	prefix := "secret/dev"
	tests := []TestSecretFromVault{
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Secret:   "https://sss/10",
			IsBase64: false,
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 404,
					Responce:     `{"errors":[]}`,
				},
			},
			Err: fmt.Errorf(fmt.Sprintf("no such secret at path '%s'", path.Join(prefix, secretPath))),
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1/secret", prefix, secretPath),
					Delay:        90, // 90 seconds
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			IsBase64: false,
			Err:      fmt.Errorf(fmt.Sprintf("can't get secret from path '%s': context deadline exceeded", path.Join(prefix, secretPath))),
			AdditionalOptions: []vault.Option{
				vault.Timeout(2),
			},
		},
	}
	for _, test := range tests {
		r2rKeys := make([]int, 0, len(test.R2R))
		for key := range test.R2R {
			r2rKeys = append(r2rKeys, key)
		}
		sort.Ints(r2rKeys)
		for _, value := range r2rKeys {
			testDoer.R2rChan <- test.R2R[value]
		}
		// default options
		options := []vault.Option{
			vault.Config(config),
			vault.Addr(config.Address, false),
			vault.Role("test"),
			vault.AuthMethod("test"),
			vault.SecretsPathPrefix(prefix),
			vault.Logger(log),
		}
		if len(test.AdditionalOptions) > 0 {
			options = append(options, test.AdditionalOptions...)
		}
		client, err := vault.New(options...)
		assert.NoError(t, err)
		sec, isBase64, err := client.GetSecretWithPrefix(prefix, secretPath)
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			continue
		}
		assert.NoError(t, err)
		assert.Equal(t, test.Secret, sec, "Secret from vault is different")
		assert.Equal(t, test.IsBase64, isBase64, "IsBase64 from vault is different")
	}
}

func TestGetSecret(t *testing.T) {
	config, ln, testDoer, err := testhelpers.HTTPServerWithAPI()
	assert.NoError(t, err)
	defer ln.Close()
	defer testDoer.Close()
	//nolint
	secretPath := "shared/test_url"
	prefix := "secret/dev"
	tests := []TestSecretFromVault{
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Secret:   "https://sss/10",
			IsBase64: false,
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"base64_value":"aHR0cHM6Ly9zc3MvMTA="},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Secret:   "aHR0cHM6Ly9zc3MvMTA=",
			IsBase64: true,
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"SomeSecret":"aHR0cHM6Ly9zc3MvMTA="},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Err: fmt.Errorf("can't get secrets value"),
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":false},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Err: fmt.Errorf("can't get secrets value"),
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":""},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			Err: fmt.Errorf("secrets value is empty"),
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath+"22"),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath+"22"),
					ResponceCode: 404,
					Responce:     `{"errors":[]}`,
				},
			},
			Err: fmt.Errorf(fmt.Sprintf("no such secret at path '%s/%s'", prefix, secretPath)),
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", prefix, secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", prefix, secretPath),
					Delay:        90, // 90 seconds
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			IsBase64: false,
			Err:      fmt.Errorf(fmt.Sprintf("can't get secret from path '%s/%s': context deadline exceeded", prefix, secretPath)),
			AdditionalOptions: []vault.Option{
				vault.Timeout(2),
			},
		},
	}
	for _, test := range tests {
		r2rKeys := make([]int, 0, len(test.R2R))
		for key := range test.R2R {
			r2rKeys = append(r2rKeys, key)
		}
		sort.Ints(r2rKeys)
		for _, value := range r2rKeys {
			testDoer.R2rChan <- test.R2R[value]
		}
		// default options
		options := []vault.Option{
			vault.Config(config),
			vault.Addr(config.Address, false),
			vault.Role("test"),
			vault.AuthMethod("test"),
			vault.SecretsPathPrefix(prefix),
			vault.Logger(log),
		}
		if len(test.AdditionalOptions) > 0 {
			options = append(options, test.AdditionalOptions...)
		}
		client, err := vault.New(options...)
		assert.NoError(t, err)
		sec, isBase64, err := client.GetSecret(secretPath)
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			continue
		}
		assert.NoError(t, err)
		assert.Equal(t, test.Secret, sec, "Secret from vault is different")
		assert.Equal(t, test.IsBase64, isBase64, "IsBase64 from vault is different")
	}
}

func TestDeleteSecret(t *testing.T) {
	config, ln, testDoer, err := testhelpers.HTTPServerWithAPI()
	assert.NoError(t, err)
	defer ln.Close()
	defer testDoer.Close()
	secretPath := "secret/dev/shared/test_url"
	tests := []TestSecretFromVault{
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", secretPath),
					ResponceCode: 204,
					Responce:     ``,
				},
			},
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", secretPath),
					Delay:        90, // 90 seconds
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			IsBase64: false,
			Err:      fmt.Errorf("can't delete secret at path 'secret/dev/shared/test_url': context deadline exceeded"),
			AdditionalOptions: []vault.Option{
				vault.Timeout(2),
			},
		},
	}
	for _, test := range tests {
		r2rKeys := make([]int, 0, len(test.R2R))
		for key := range test.R2R {
			r2rKeys = append(r2rKeys, key)
		}
		sort.Ints(r2rKeys)
		for _, value := range r2rKeys {
			testDoer.R2rChan <- test.R2R[value]
		}
		// default options
		options := []vault.Option{
			vault.Config(config),
			vault.Addr(config.Address, false),
			vault.Role("test"),
			vault.AuthMethod("test"),
			vault.SecretsPathPrefix("some"),
			vault.Logger(log),
		}
		if len(test.AdditionalOptions) > 0 {
			options = append(options, test.AdditionalOptions...)
		}
		client, err := vault.New(options...)
		assert.NoError(t, err)
		err = client.DeleteSecret(secretPath)
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			continue
		}
		assert.NoError(t, err)
	}
}

func TestCreateSecret(t *testing.T) {
	config, ln, testDoer, err := testhelpers.HTTPServerWithAPI()
	assert.NoError(t, err)
	defer ln.Close()
	defer testDoer.Close()
	secretPath := "secret/dev/shared/test_url"
	tests := []TestSecretFromVault{
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", secretPath),
					ResponceCode: 204,
					Responce:     ``,
				},
			},
		},
		{
			R2R: map[int]testhelpers.Responce2Req{
				1: {
					RequestURI:   path.Join("/v1/sys/internal/ui/mounts", secretPath),
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"204609fa-02b4-e56f-803c-119c0fef255f","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"kv_ab99964e","config":{"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0},"description":"key/value secret storage","external_entropy_access":false,"local":false,"options":{"version":"1"},"path":"secret/","seal_wrap":false,"type":"kv","uuid":"c7415bec-f301-0c14-2c48-6d17d549aba1"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
				2: {
					RequestURI:   path.Join("/v1", secretPath),
					Delay:        90, // 90 seconds
					ResponceCode: 200,
					//nolint
					Responce: `{"request_id":"ba0f8d29-262b-db3a-3660-746f593c97a7","lease_id":"","renewable":false,"lease_duration":2764800,"data":{"value":"https://sss/10"},"wrap_info":null,"warnings":null,"auth":null}`,
				},
			},
			IsBase64: false,
			Err:      fmt.Errorf("can't write secret to path 'secret/dev/shared/test_url': context deadline exceeded"),
			AdditionalOptions: []vault.Option{
				vault.Timeout(2),
			},
		},
	}
	for _, test := range tests {
		r2rKeys := make([]int, 0, len(test.R2R))
		for key := range test.R2R {
			r2rKeys = append(r2rKeys, key)
		}
		sort.Ints(r2rKeys)
		for _, value := range r2rKeys {
			testDoer.R2rChan <- test.R2R[value]
		}
		// default options
		options := []vault.Option{
			vault.Config(config),
			vault.Addr(config.Address, false),
			vault.Role("test"),
			vault.AuthMethod("test"),
			vault.SecretsPathPrefix("some"),
			vault.Logger(log),
		}
		if len(test.AdditionalOptions) > 0 {
			options = append(options, test.AdditionalOptions...)
		}
		client, err := vault.New(options...)
		assert.NoError(t, err)
		data := make(map[string]interface{}, 1)
		data["test"] = "value"
		err = client.CreateSecret(secretPath, data)
		if test.Err != nil {
			assert.EqualError(t, err, fmt.Sprintf("%s", test.Err))
			continue
		}
		assert.NoError(t, err)
	}
}
