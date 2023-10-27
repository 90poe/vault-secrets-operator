package controllers

import (
	"context"
	"fmt"

	"github.com/90poe/vault-secrets-operator/internal/config"
	"github.com/90poe/vault-secrets-operator/internal/vault"
	"github.com/90poe/vault-secrets-operator/internal/vaultclient"
	"github.com/go-logr/logr"
)

// createVaultClient will return vault client
func createVaultClient(ctx context.Context, vaultInt vault.Client, reqLogger logr.Logger) (*vaultclient.Client, error) {
	c := config.Get()
	vaultInt.SetContext(ctx)
	vault, err := vaultclient.New(
		vaultclient.VaultClient(vaultInt),
		vaultclient.SecretsPathPrefix(c.VaultSecretsPrefix),
		vaultclient.TLSCertsCachePath(c.VaultTLSCachePath),
		vaultclient.Logger(reqLogger),
	)
	if err != nil {
		return nil, fmt.Errorf("can't get vault client: %w", err)
	}
	return vault, nil
}
