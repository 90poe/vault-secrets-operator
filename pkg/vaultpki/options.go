package vaultpki

import (
	"fmt"

	"github.com/90poe/vault-secrets-operator/pkg/vault"
)

//Option is a type of options for Vault Client
type Option func(*TLSCert) error

//Profile is option function to set profile in Vault
func Profile(profile string) Option {
	return func(t *TLSCert) error {
		if len(profile) == 0 {
			return fmt.Errorf("profile in Vault can't be empty")
		}
		t.profile = profile
		return nil
	}
}

//VaultClient is option function to set vault client
func VaultClient(client *vault.Client) Option {
	return func(t *TLSCert) error {
		if client == nil {
			return fmt.Errorf("Vault client can't be empty")
		}
		t.client = client
		return nil
	}
}
