package vault

import (
	"context"
	"fmt"
	"reflect"

	"github.com/go-logr/logr"
)

// Option is a type of options for Vault Client
type Option func(*vaultClient) error

// ContextWithCancelFN is option function to set channel for termination notifications from renew
// and also set upstream context
func ContextWithCancelFN(ctx context.Context, cancelFn context.CancelFunc) Option {
	return func(c *vaultClient) error {
		if !reflect.ValueOf(ctx).IsValid() {
			return fmt.Errorf("context can't be empty")
		}
		c.ctx = ctx
		if !reflect.ValueOf(cancelFn).IsValid() {
			return fmt.Errorf("cancel function can't be empty")
		}
		c.cancelFn = cancelFn
		return nil
	}
}

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
