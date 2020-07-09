package config

import (
	"sync"

	"github.com/90poe/vault-secrets-operator/pkg/utils"
)

type cfg struct {
	VaultAddr          string
	VaultSkipVerify    string
	VaultRole2Assume   string
	VaultSecretsPrefix string
}

var doOnce sync.Once
var config *cfg

//Get would get config
func Get() *cfg {
	doOnce.Do(func() {
		config = &cfg{}
		config.VaultAddr = utils.MustGetEnv("VAULT_ADDR")
		config.VaultSkipVerify = utils.MustGetEnv("VAULT_SKIP_VERIFY")
		config.VaultRole2Assume = utils.MustGetEnv("VAULT_ROLE_2_ASSUME")
		config.VaultSecretsPrefix = utils.MustGetEnv("VAULT_SECRETS_PREFIX")
	})
	return config
}
