package vault

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
)

// kvPreflightVersionRequest checks which version of the key values secrets
// engine is used for the given path.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L44
func (v *vaultClient) kvPreflightVersionRequest(path string) (string, int, error) {
	// We don't want to use a wrapping call here so save any custom value and
	// restore after
	currentWrappingLookupFunc := v.client.CurrentWrappingLookupFunc()
	v.client.SetWrappingLookupFunc(nil)
	defer v.client.SetWrappingLookupFunc(currentWrappingLookupFunc)
	currentOutputCurlString := v.client.OutputCurlString()
	v.client.SetOutputCurlString(false)
	defer v.client.SetOutputCurlString(currentOutputCurlString)

	r := v.client.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	//nolint
	resp, err := v.client.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// If we get a 404 we are using an older version of vault, default to
		// version 1
		if resp != nil && resp.StatusCode == 404 {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	if secret == nil {
		return "", 0, errors.New("nil response from pre-flight request")
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath, ok = mountPathRaw.(string)
		if !ok {
			return "", 0, errors.New("can't cast mountPath to string")
		}
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version, ok := versionRaw.(string)
	if !ok {
		return mountPath, 1, nil
	}
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

// isKVv2 returns true if a KVv2 is used for the given path and false if a KVv1
// secret engine is used.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L99
func (v *vaultClient) isKVv2(path string) (string, bool, error) {
	mountPath, version, err := v.kvPreflightVersionRequest(path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

// addPrefixToVKVPath adds the given prefix to the given path.
// This function is copy/past from the github.com/hashicorp/vault repository,
// see: https://github.com/hashicorp/vault/blob/f843c09dd15ca4982e60fa12dea48c8f7d7e0373/command/kv_helpers.go#L108
func (v *vaultClient) addPrefixToVKVPath(p, mountPath, apiPrefix string) string {
	switch {
	case p == mountPath, p == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		p = strings.TrimPrefix(p, mountPath)
		return path.Join(mountPath, apiPrefix, p)
	}
}

func (v *vaultClient) fixPath(path string) string {
	// Check if the KVv1 or KVv2 is used for the provided secret and determin
	// the mount path of the secrets engine.
	mountPath, v2, err := v.isKVv2(path)
	if err != nil {
		// We can't check if path is v2 or not, thus returning path as it is
		v.logger.Error(fmt.Errorf("can't check if path is v2 or not"), "")
		return path
	}

	if v2 {
		path = v.addPrefixToVKVPath(path, mountPath, "data")
	}
	return path
}
