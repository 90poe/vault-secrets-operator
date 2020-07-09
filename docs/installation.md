# vaultsecrets-operator installation

The contains details of how to install and uninstall vaultsecrets-operator

## Requirements

vaultsecrets-operator runs on K8S cluster 1.16 and up. To install it you would need:
1. Admin access to cluster
2. `kubectl` which is configured to access your cluster and is in your execution path
3. GNU or *NIX Make which is in your execution path

## Install to K8S cluster

The vaultsecrets-operator docker image is located at [DockerHub](https://hub.docker.com/repository/docker/90poe/vaultsecrets-operators).

To install it to your K8S cluster:
1. edit `deploy/operator.yaml` and add your environment variables.
2. Install using `make` and `kubectl`:
```
cd deploy
make install
```

## EnvVariables

Environment variables, which allow to configure operator:

|Variable Name|Required|Notes|Example|
|-------------|:------|:---|:------|
|VAULT_ADDR|Yes|FQDN with port of your Vault installtion. Operator from K8S must be able to access it.|https://vault.default.svc.cluster.local:8200|
|VAULT_SKIP_VERIFY|No|Operator will allow TLS connections to Vault, protected with self signed certificate|1|
|VAULT_ROLE_2_ASSUME|Yes|Role to assume on Vault|vault-secret-operator-role|
|VAULT_SECRETS_PREFIX|Yes|Path in Vault, where your secrets are kept|secret/k8s|
