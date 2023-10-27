package vaultclient

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/90poe/vault-secrets-operator/internal/vault"
	"github.com/go-logr/logr"
)

// Option is a type of options for Vault Client
type Option func(*Client) error

// VaultClient will add interface to vault client, can be mocked
func VaultClient(client vault.Client) Option {
	return func(c *Client) error {
		if !reflect.ValueOf(client).IsValid() {
			return fmt.Errorf("invalid vault client interface")
		}
		c.client = client
		return nil
	}
}

// SecretsPathPrefix is option function to set Vault secrets path prefix
func SecretsPathPrefix(prefix string) Option {
	return func(c *Client) error {
		prefix = strings.Trim(prefix, " ")
		if len(prefix) == 0 {
			return fmt.Errorf("prefix to secrets within Vault can't be empty")
		}
		c.secretsPathPrefix = prefix
		return nil
	}
}

// TLSCertsCachePath is option function to set Vault TLS certs cache path
func TLSCertsCachePath(path string) Option {
	return func(c *Client) error {
		path = strings.Trim(path, " ")
		if len(path) == 0 {
			return fmt.Errorf("prefix to secrets within Vault can't be empty")
		}
		c.tlsCertsCachePath = path
		return nil
	}
}

// Logger will add logger to Vault client
func Logger(logger logr.Logger) Option {
	return func(c *Client) error {
		if !reflect.ValueOf(logger).IsValid() {
			return fmt.Errorf("logger for Vault Client is not valid")
		}
		c.logger = logger
		return nil
	}
}
