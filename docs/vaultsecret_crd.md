# VaultSecret CRD

Example:
```
apiVersion: xo.90poe.io/v1alpha1
kind: VaultSecret
metadata:
  name: example-vaultsecret
  labels:
    app: example-vaultsecret-app
    owner: DevOps
spec:
  name: default-v1-test
  reread_intervals: 300 # 10 minutes
  type: kubernetes.io/dockerconfigjson
  secrets_paths:
    .dockerconfigjson: shared/nexus_dockerconfigjson
```

## Spec

You will have to amend `spec` section according to your requirements.

Spec section:

|Settings|Type |Required|Notes|
|--------|:---|:------|:---|
|name|string|Yes|Name of Secret in K8S|
|secrets_paths|map[string]string|Yes|List of Vault secrets you want to be added to K8S. See <a href="#SecretsPaths">SecretsPaths</a> for more details.|
|reread_intervals|int|Yes|Seconds how often to re-read secrets values from Vault|
|type|v1.Secret K8S object Type string|Yes|Type of K8S secret, please see Kubernetes [docs](https://kubernetes.io/docs/concepts/configuration/secret/)|

## SecretsPaths
<a name="SecretPaths"></a>
This map contains `keys` and `values`. `Keys` would be used in Secrets as data keys. And values would be fetched from Vault on path, specified by `values` in this structure.

Full path, on which this operator is going to read secret from Vault is constructed as follows:
**VAULT_SECRETS_PREFIX** / + value

NOTE: **VAULT_SECRETS_PREFIX** is environment variable.

Example:
```
spec:
  ....
  secrets_paths:
    SOME_DATA: shared/very_secure_password
```

In here, `SOME_DATA` will be put to K8S secret as data key and value for it would be fetched from `$VAULT_SECRETS_PREFIX/shared/very_secure_password` in Vault.

Operator is expecting special form for secret in Vault.
You must have secret `shared/very_secure_password` hold key `value` or `base64_value` and your secret. If `value` is used for key in Vault, secret will be encoded with base64 before putting into K8S Secret object.
If `base64_value` value is used (for binary or JSON objects), then oeprator expects that value is already encoded in Vault and will not perform additional encodind before putting to K8S Secret object.
