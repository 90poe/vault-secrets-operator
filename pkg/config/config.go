package config

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/90poe/vault-secrets-operator/pkg/utils"
)

type PKI struct {
	PKIPath string `json:"path"`
	PKIRole string `json:"role"`
}

type Cfg struct {
	VaultAddr               string
	VaultSkipVerify         string
	VaultRole2Assume        string
	VaultSecretsPrefix      string
	VaultTLSCachePath       string
	MaxConcurrentReconciles int
	PKIs                    map[string]string
}

var doOnce sync.Once
var config *Cfg

// Get would get config
func Get() *Cfg {
	doOnce.Do(func() {
		config = &Cfg{
			PKIs: map[string]string{},
		}
		config.VaultAddr = utils.MustGetEnv("VAULT_ADDR")
		config.VaultSkipVerify = utils.MustGetEnv("VAULT_SKIP_VERIFY")
		config.VaultRole2Assume = utils.MustGetEnv("VAULT_ROLE_2_ASSUME")
		config.VaultSecretsPrefix = utils.MustGetEnv("VAULT_SECRETS_PREFIX")
		config.VaultTLSCachePath = utils.MustGetEnv("VAULT_TLS_CACHE_PATH")
		config.MaxConcurrentReconciles = utils.MustGetEnvInt("MAX_CONCURRENT_RECONCILES")
		initPkis(config)
	})
	return config
}

func initPkis(cfg *Cfg) {
	pkisStr := utils.MustGetEnv("PKIS")
	pkis := []PKI{}
	err := json.Unmarshal([]byte(pkisStr), &pkis)
	if err != nil {
		log.Fatalf("environment variable PKIS is missing or invalid: %v", err)
	}
	for _, pki := range pkis {
		cfg.PKIs[pki.PKIPath] = pki.PKIRole
	}
}
