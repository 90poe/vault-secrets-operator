package config

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/ilyakaznacheev/cleanenv"
)

type PKI struct {
	PKIPath string `json:"path"`
	PKIRole string `json:"role"`
}

type PKIs map[string]string

type Cfg struct {
	VaultAddr               string `env:"VAULT_ADDR" env-default:""`
	VaultSkipVerify         string `env:"VAULT_SKIP_VERIFY" env-default:"1"`
	VaultRole2Assume        string `env:"VAULT_ROLE_2_ASSUME" env-default:""`
	VaultSecretsPrefix      string `env:"VAULT_SECRETS_PREFIX" env-default:""`
	VaultTLSCachePath       string `env:"VAULT_TLS_CACHE_PATH" env-default:""`
	MaxConcurrentReconciles int    `env:"MAX_CONCURRENT_RECONCILES" env-default:"2"`
	PKIs                    PKIs   `env:"PKIS" env-default:""`
}

var doOnce sync.Once
var config *Cfg

// Get would get config
func Get() *Cfg {
	doOnce.Do(func() {
		config = &Cfg{
			PKIs: map[string]string{},
		}
		err := cleanenv.ReadEnv(config)
		if err != nil {
			log.Fatalf("environment variable PKIS is missing or invalid: %v", err)
		}
	})
	return config
}

func (s *PKIs) SetValue(pkisStr string) error {
	pkis := []PKI{}
	err := json.Unmarshal([]byte(pkisStr), &pkis)
	if err != nil {
		log.Fatalf("environment variable PKIS is invalid: %v", err)
	}
	for _, pki := range pkis {
		(*s)[pki.PKIPath] = pki.PKIRole
	}
	return nil
}
