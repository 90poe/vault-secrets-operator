package vault

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

//Option is a type of options for Vault Client
type Option func(*Client) error

//Addr is option function to set Vault Addr for Client
func Addr(addr string, skipVerify bool) Option {
	return func(c *Client) error {
		addr = strings.Trim(addr, " ")
		pattern, err := regexp.Compile(consts.URLCheckRegexpPattern)
		if err != nil {
			return fmt.Errorf("can't compile URL check pattern: %w", err)
		}
		if len(addr) == 0 {
			return fmt.Errorf("address for Vault can't be empty")
		}
		if !pattern.MatchString(addr) {
			return fmt.Errorf("invalid Vault URL address")
		}
		c.address = addr
		c.skipVerify = skipVerify
		return nil
	}
}

//Role is option function to set Vault login role for Client
func Role(role string) Option {
	return func(c *Client) error {
		role = strings.Trim(role, " ")
		if len(role) == 0 {
			return fmt.Errorf("role to login with to Vault can't be empty")
		}
		c.role = role
		return nil
	}
}

//SecretsPathPrefix is option function to set Vault secrets path prefix
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

//ContextWithCancelFN is option function to set channel for termination notifications from renew
// and also set upstream context
func ContextWithCancelFN(ctx context.Context, cancelFn context.CancelFunc) Option {
	return func(c *Client) error {
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

//AuthMethod is option function to set Vault authentication method, only possibles are aws (default) and test (for testing)
func AuthMethod(authMethod string) Option {
	return func(c *Client) error {
		authMethod = strings.ToLower(strings.Trim(authMethod, " "))
		if (authMethod != "aws") && (authMethod != "test") {
			return fmt.Errorf("authMethod can be only (aws|test), %s is invalid", authMethod)
		}
		c.authMethod = authMethod
		return nil
	}
}

//Timeout is option function to set Vault http client timeout
func Timeout(timeout int) Option {
	return func(c *Client) error {
		c.timeout = timeout
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

//Config is option function to set Vault config (for test purposes mainly)
func Config(config *api.Config) Option {
	return func(c *Client) error {
		if config == nil {
			return fmt.Errorf("config for Vault can't be empty")
		}
		c.config = config
		return nil
	}
}
