package vault

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/go-logr/logr"
	hvault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/aws"
)

//go:generate mockgen -destination=../mocks/$GOPACKAGE/client.go -package=$GOPACKAGE -source client.go
//go:generate gofmt -s -l -w ../mocks/$GOPACKAGE/client.go

type Client interface {
	Read(path string) (*hvault.Secret, error)
	Write(path string, data map[string]interface{}) (*hvault.Secret, error)
	Delete(path string) (*hvault.Secret, error)
	Address() string
}

type vaultClient struct {
	ctx      context.Context
	cancelFn context.CancelFunc
	client   *hvault.Client
	address  string
	role     string
	logger   logr.Logger
}

func New(address, role string, skipVerify bool, options ...Option) (Client, error) {
	// return actual client
	cl := &vaultClient{
		role:    role,
		address: address,
	}
	var err error
	for _, option := range options {
		err = option(cl)
		if err != nil {
			return nil, fmt.Errorf("can't make new Vault: %w", err)
		}
	}
	err = cl.verify()
	if err != nil {
		return nil, err
	}

	// setup env
	err = os.Setenv("VAULT_ADDR", cl.address)
	if err != nil {
		return nil, err
	}
	skipV := "0"
	if skipVerify {
		skipV = "1"
	}
	err = os.Setenv("VAULT_SKIP_VERIFY", skipV)
	if err != nil {
		return nil, err
	}
	// Get real Vault client
	config := hvault.DefaultConfig()
	config.Timeout = time.Duration(consts.VaultClientTimeoutSec) * time.Second
	cl.client, err = hvault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("can't create Vault API VClient: %w", err)
	}
	err = cl.getToken()
	if err != nil {
		return nil, err
	}
	go cl.renewToken()
	return cl, nil
}

// verify helper function which will verify our vault client struct is correct
func (v *vaultClient) verify() error {
	// verify address
	v.address = strings.Trim(v.address, " \t")
	v.role = strings.Trim(v.role, " \t")
	pattern := regexp.MustCompile(consts.URLCheckRegexpPattern)
	if len(v.address) == 0 {
		return fmt.Errorf("address for Vault can't be empty")
	}
	if !pattern.MatchString(v.address) {
		return fmt.Errorf("invalid Vault URL address")
	}
	// verify role
	if len(v.role) == 0 {
		return fmt.Errorf("can't use empty Vault role")
	}
	// verify logger
	if !reflect.ValueOf(v.logger.GetSink()).IsValid() {
		return fmt.Errorf("can't use empty logger")
	}
	// verify context and cancel func
	if !reflect.ValueOf(v.ctx).IsValid() {
		return fmt.Errorf("can't use empty context")
	}
	if v.cancelFn == nil {
		return fmt.Errorf("can't use nil cancel func")
	}
	return nil
}

// Interface implementation functions
func (v *vaultClient) Read(path string) (*hvault.Secret, error) {
	logical := v.client.Logical()
	return logical.Read(v.fixPath(path))
}

func (v *vaultClient) Write(path string, data map[string]interface{}) (*hvault.Secret, error) {
	logical := v.client.Logical()
	return logical.Write(v.fixPath(path), data)
}

func (v *vaultClient) Delete(path string) (*hvault.Secret, error) {
	logical := v.client.Logical()
	return logical.Delete(v.fixPath(path))
}

func (v *vaultClient) Address() string {
	return v.client.Address()
}

// getToken would get token after login 2 AWS
func (v *vaultClient) getToken() error {
	awsAuth, err := aws.NewAWSAuth(
		aws.WithIAMAuth(),
		aws.WithRole(v.role),
		aws.WithRegion("us-east-1"),
	)

	if err != nil {
		return fmt.Errorf("unable to create vault AWS auth client: %w", err)
	}
	apiSecret, err := awsAuth.Login(v.ctx, v.client)
	if err != nil || apiSecret == nil {
		return fmt.Errorf("unable to login with vault AWS auth client or apiSecret is nil: %w", err)
	}
	// Set token
	v.client.SetToken(apiSecret.Auth.ClientToken)
	return nil
}

// RenewToken renews the provided token after the half of the lease duration is
// passed.
func (v *vaultClient) renewToken() {
	v.logger.Info("Launching Vault Token renew routine")
	tokenSec, err := v.client.Auth().Token().LookupSelf()
	if err != nil {
		v.logger.Error(err, "could not get token")
		return
	}
	ttl, err := tokenSec.TokenTTL()
	if err != nil {
		v.logger.Error(err, "could not get token ttl")
		return
	}
	// Renew token when it has expired 70% of it's time
	renewDur := time.Duration(ttl.Seconds() * 0.7)
	ticker := time.NewTicker(renewDur * time.Second)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			v.logger.Info(fmt.Sprintf("renew Vault token at time: %v", t), "Renew.Time", t)
			err = v.getToken()
			if err != nil {
				v.logger.Error(err, "could not renew token")
				v.cancelFn()
			}
		case <-v.ctx.Done():
			return
		}
	}
}
