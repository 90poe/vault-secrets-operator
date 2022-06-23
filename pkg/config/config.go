package config

import (
	"sync"

	"github.com/90poe/vault-secrets-operator/pkg/utils"
)

type Cfg struct {
	VaultAddr               string
	VaultSkipVerify         string
	VaultRole2Assume        string
	VaultSecretsPrefix      string
	MaxConcurrentReconciles int
}

var doOnce sync.Once
var config *Cfg

// Get would get config
func Get() *Cfg {
	doOnce.Do(func() {
		config = &Cfg{}
		config.VaultAddr = utils.MustGetEnv("VAULT_ADDR")
		config.VaultSkipVerify = utils.MustGetEnv("VAULT_SKIP_VERIFY")
		config.VaultRole2Assume = utils.MustGetEnv("VAULT_ROLE_2_ASSUME")
		config.VaultSecretsPrefix = utils.MustGetEnv("VAULT_SECRETS_PREFIX")
		config.MaxConcurrentReconciles = utils.MustGetEnvInt("MAX_CONCURRENT_RECONCILES")
	})
	return config
}
