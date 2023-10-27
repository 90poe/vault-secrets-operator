package vault

import (
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
)

// Option is a type of options for Vault Client
type Option func(*vaultClient) error

// Logger will add logger to Vault client
func Logger(logger logr.Logger) Option {
	return func(c *vaultClient) error {
		if !reflect.ValueOf(logger).IsValid() {
			return fmt.Errorf("logger for Vault Client is not valid")
		}
		c.logger = logger
		return nil
	}
}
