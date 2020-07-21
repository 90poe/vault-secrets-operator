package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/90poe/vault-secrets-operator/pkg/consts"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-logr/logr"
	"github.com/hashicorp/vault/api"
	"golang.org/x/net/context"
)

//Client struct would hold connection to Vault
type Client struct {
	address           string
	skipVerify        bool
	role              string
	secretsPathPrefix string
	authMethod        string
	timeout           int
	logger            logr.Logger
	config            *api.Config
	connection        *api.Client
	ctx               context.Context
	cancelFn          context.CancelFunc
	pkis2Clean        map[string]bool
	pkis2CleanChan    chan string
}

//New would create Vault Client
func New(options ...Option) (*Client, error) {
	c := Client{
		authMethod:     "aws",
		timeout:        consts.VaultClientTimeoutSec,
		pkis2Clean:     make(map[string]bool),
		pkis2CleanChan: make(chan string),
	}
	// Default empty ctx with Cancel function
	c.ctx, c.cancelFn = context.WithCancel(context.Background())
	var err error
	for _, option := range options {
		err = option(&c)
		if err != nil {
			return nil, fmt.Errorf("can't make new Vault Client: %w", err)
		}
	}
	err = c.verify()
	if err != nil {
		return nil, err
	}
	//setup env
	err = os.Setenv("VAULT_ADDR", c.address)
	if err != nil {
		return nil, err
	}
	skipVerify := "0"
	if c.skipVerify {
		skipVerify = "1"
	}
	err = os.Setenv("VAULT_SKIP_VERIFY", skipVerify)
	if err != nil {
		return nil, err
	}

	//Get Vault client
	err = c.getVaultClient()
	if err != nil {
		return nil, err
	}
	if c.authMethod == "aws" {
		err = c.getToken()
		if err != nil {
			return nil, err
		}
		go c.renewToken()
	}
	// PKI's Tidy job
	go c.pkiTidy()
	return &c, nil
}

//Logical would return Logical client of Vault
func (c *Client) Logical() *api.Logical {
	return c.connection.Logical()
}

//Address would return Vault HTTP(s) address
func (c *Client) Address() string {
	return c.address
}

//SkipVerify would return if we should skip Vault TLS cert verification
func (c *Client) SkipVerify() bool {
	return c.skipVerify
}

//AddPKI2Clean would add your PKI to cleanup
func (c *Client) AddPKI2Clean(pkiPath string) {
	c.pkis2CleanChan <- pkiPath
}

// GetSecret would return string (if found), bool that secret is base64 binary,
// error if something gets wrong
func (c *Client) GetSecret(secretPath string) (string, bool, error) {
	secretPath = path.Join(c.secretsPathPrefix, secretPath)

	return c.getSecretRaw(secretPath)
}

// GetSecretWithPrefix would return string (if found), bool that secret is base64 binary,
// error if something gets wrong
func (c *Client) GetSecretWithPrefix(prefix, secretPath string) (string, bool, error) {
	secretPath = path.Join(prefix, secretPath)

	return c.getSecretRaw(secretPath)
}

// GetRawSecret would get raw (unparsed secret) from Vault
func (c *Client) GetRawSecret(fullPath string) (*api.Secret, error) {
	logical := c.connection.Logical()

	// Check if the KVv1 or KVv2 is used for the provided secret and determin
	// the mount path of the secrets engine.
	mountPath, v2, err := c.isKVv2(fullPath)
	if err != nil {
		return nil, fmt.Errorf("can't check if path is V2 or not: %w", err)
	}

	if v2 {
		fullPath = c.addPrefixToVKVPath(fullPath, mountPath, "data")
	}
	secret, err := logical.Read(fullPath)
	if err != nil {
		return nil, fmt.Errorf("can't get secret from path '%s': %w", fullPath, err)
	}
	return secret, err
}

//DeleteSecret would delete secret from Vault
func (c *Client) DeleteSecret(fullPath string) error {
	logical := c.connection.Logical()

	// Check if the KVv1 or KVv2 is used for the provided secret and determin
	// the mount path of the secrets engine.
	mountPath, v2, err := c.isKVv2(fullPath)
	if err != nil {
		return fmt.Errorf("can't check if path is V2 or not: %w", err)
	}

	if v2 {
		fullPath = c.addPrefixToVKVPath(fullPath, mountPath, "data")
	}

	_, err = logical.Delete(fullPath)
	if err != nil {
		return fmt.Errorf("can't delete secret at path '%s': %w", fullPath, err)
	}
	return nil
}

//CreateSecret would create secret in Vault
func (c *Client) CreateSecret(fullPath string, data map[string]interface{}) error {
	logical := c.connection.Logical()

	// Check if the KVv1 or KVv2 is used for the provided secret and determin
	// the mount path of the secrets engine.
	mountPath, v2, err := c.isKVv2(fullPath)
	if err != nil {
		return fmt.Errorf("can't check if path is V2 or not: %w", err)
	}

	if v2 {
		fullPath = c.addPrefixToVKVPath(fullPath, mountPath, "data")
	}

	_, err = logical.Write(fullPath, data)
	if err != nil {
		return fmt.Errorf("can't write secret to path '%s': %w", fullPath, err)
	}
	return nil
}

func (c *Client) getSecretRaw(fullPath string) (string, bool, error) {
	isBinary := false
	// Get raw secret from Vault
	secret, err := c.GetRawSecret(fullPath)
	if err != nil {
		return "", isBinary, err
	}
	if secret == nil {
		return "", isBinary, fmt.Errorf("no such secret at path '%s'", fullPath)
	}
	// Read secret, as we know format we expect
	value, ok := secret.Data[consts.VaultPlainValueKey]
	if !ok {
		value, ok = secret.Data[consts.VaultBase64ValueKey]
		if !ok {
			return "", isBinary, fmt.Errorf("can't get secrets value")
		}
		isBinary = true
	}
	sValue, ok := value.(string)
	if !ok {
		return "", isBinary, fmt.Errorf("can't get secrets value")
	}
	if len(sValue) == 0 {
		return "", isBinary, fmt.Errorf("secrets value is empty")
	}
	return sValue, isBinary, nil
}

// GetSecretData will return secret data as string from path dataPath
func (c *Client) GetSecretData(secret *api.Secret, dataPath string) (string, error) {
	// Read secret, as we know format we expect
	value, ok := secret.Data[dataPath]
	if !ok {
		return "", fmt.Errorf("can't get secrets value from path %s", dataPath)
	}
	sValue, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("can't get secrets bytes")
	}
	return sValue, nil
}

//getVaultClient would try to connect to Vault as Client
func (c *Client) getVaultClient() error {
	// Create new Vault configuration. This configuration is used to create the
	// API client. We set the timeout of the HTTP client to 60 seconds.
	// See: https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779
	if c.config == nil {
		c.config = api.DefaultConfig()
	}
	c.config.Timeout = time.Duration(c.timeout) * time.Second
	client, err := api.NewClient(c.config)
	if err != nil {
		return fmt.Errorf("can't create Vault API VClient: %w", err)
	}
	c.connection = client
	return nil
}

// Generates the necessary data to send to the Vault server for generating a token
// This is useful for other API VClients to use
func generateLoginData() (map[string]interface{}, error) {
	loginData := make(map[string]interface{})

	// Use the credentials we've found to construct an STS session
	stsSession, err := session.NewSessionWithOptions(session.Options{})
	if err != nil {
		return nil, fmt.Errorf("can't create stsSession: %w", err)
	}

	var params *sts.GetCallerIdentityInput
	svc := sts.New(stsSession)
	stsRequest, _ := svc.GetCallerIdentityRequest(params)

	err = stsRequest.Sign()
	if err != nil {
		return nil, fmt.Errorf("can't sign stsSession: %w", err)
	}

	// Now extract out the relevant parts of the request
	headersJSON, err := json.Marshal(stsRequest.HTTPRequest.Header)
	if err != nil {
		return nil, fmt.Errorf("can't marshal headersJSON: %w", err)
	}
	requestBody, err := ioutil.ReadAll(stsRequest.HTTPRequest.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read request body: %w", err)
	}
	loginData["iam_http_request_method"] = stsRequest.HTTPRequest.Method
	loginData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(stsRequest.HTTPRequest.URL.String()))
	loginData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headersJSON)
	loginData["iam_request_body"] = base64.StdEncoding.EncodeToString(requestBody)

	return loginData, nil
}

//getToken would get token after login
func (c *Client) getToken() error {
	loginData, err := generateLoginData()
	logical := c.connection.Logical()
	if err != nil {
		return fmt.Errorf("can't generateLoginData: %w", err)
	}
	data := make(map[string]interface{}, 5)
	data["role"] = c.role
	data["iam_request_url"] = loginData["iam_request_url"]
	data["iam_request_body"] = loginData["iam_request_body"]
	data["iam_request_headers"] = loginData["iam_request_headers"]
	data["iam_http_request_method"] = loginData["iam_http_request_method"]
	secret, err := logical.Write("auth/aws/login", data)
	if err != nil {
		return fmt.Errorf("can't login to auth/aws/login: %w", err)
	}
	if secret.Auth == nil || len(secret.Auth.ClientToken) == 0 {
		return fmt.Errorf("there is no such member Auth.ClientToken in data")
	}
	c.connection.SetToken(secret.Auth.ClientToken)
	return nil
}

func (c *Client) verify() error {
	if len(strings.Trim(c.address, " ")) == 0 {
		return fmt.Errorf("can't use empty Vault address")
	}
	if len(strings.Trim(c.role, " ")) == 0 {
		return fmt.Errorf("can't use empty Vault role")
	}
	if !reflect.ValueOf(c.logger).IsValid() {
		return fmt.Errorf("can't use empty logger")
	}
	return nil
}

// RenewToken renews the provided token after the half of the lease duration is
// passed.
func (c *Client) renewToken() {
	c.logger.Info("Launching Vault Token renew routine")
	tokenSec, err := c.connection.Auth().Token().LookupSelf()
	if err != nil {
		c.logger.Error(err, "could not get token")
		return
	}
	ttl, err := tokenSec.TokenTTL()
	if err != nil {
		c.logger.Error(err, "could not get token ttl")
		return
	}
	// Renew token when it has expired 70% of it's time
	renewDur := time.Duration(ttl.Seconds() * 0.7)
	ticker := time.NewTicker(renewDur * time.Second)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			c.logger.Info(fmt.Sprintf("renew Vault token at time: %v", t), "Renew.Time", t)
			err = c.getToken()
			if err != nil {
				c.logger.Error(err, "could not renew token")
				c.cancelFn()
			}
		case <-c.ctx.Done():
			return
		}
	}
}

//pkiTidy would issue Tidy API call
func (c *Client) pkiTidy() {
	c.logger.Info("Launching PKI Tidy routine")
	// Run PKI Tidy every 24 hours
	ticker := time.NewTicker(consts.VaultPKICleanupInHours * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			c.logger.Info(fmt.Sprintf("run PKI Tidy at: %v", t))
			for pki := range c.pkis2Clean {
				err := c.issuePkiTidy(pki)
				if err != nil {
					c.logger.Error(err, fmt.Sprintf("could not issue tidy up PKI request '%s'", pki))
					c.cancelFn()
				}
			}
		case pkiPath := <-c.pkis2CleanChan:
			c.pkis2Clean[pkiPath] = true
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) issuePkiTidy(pki string) error {
	logical := c.connection.Logical()
	data := make(map[string]interface{}, 3)
	data["tidy_cert_store"] = true
	data["tidy_revoked_certs"] = true
	data["safety_buffer"] = "1h"
	_, err := logical.Write(fmt.Sprintf("%s/tidy", pki), data)
	if err != nil {
		return fmt.Errorf("can't tidy up: %w", err)
	}
	return nil
}
