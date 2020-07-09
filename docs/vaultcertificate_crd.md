# VaultCertificate Template CRD

**NOTE: Functionality is still in Alpha stage, use at your own risk**

Example:
```
apiVersion: xo.90poe.io/v1alpha1
kind: VaultCertificate
metadata:
  name: example-vaultcertificate
spec:
  name: cert-secretfromvault-tls
  reread_intervals: 300 # 10 minutes
  type: kubernetes.io/tls
  tls_certs:
  - vault_pki_profile: k8s
    common_name: short-cert
    ttl: 1
    ca_cert_key_name: ca.crt
    cert_key_name: tls.crt
    private_key_name: tls.key
```

## Spec

You will have to amend `spec` section according to your requirements.

Spec section:

|Settings|Type |Required|Notes|
|--------|:---|:------|:---|
|name|string|Yes|Name of Secret in K8S|
|reread_intervals|int|Yes|Seconds how often to re-read TLS certificate from Vault. If Certificate is expired - it will be re-issued. Suggest to keep shorter than TTL of cert|
|type|v1.Secret K8S object Type string|Yes|Type of K8S secret, please see Kubernetes [docs](https://kubernetes.io/docs/concepts/configuration/secret/)|
|tls_certs|[]TLSCertificate|Yes|List of certificates you want to be issued. See <a href="#TLSCertificate">TLSCertificate</a> for more details of item.|

## TLSCertificate
<a name="TLSCertificate"></a>

|Settings|Type |Required|Notes|
|--------|:---|:------|:---|
|vault_pki_profile|string|Yes|See <a href="#PKIProfile">PKIProfile</a> for more details of item.|
|common_name|string|Yes|Common name of certificate. It should be in short form as `domain` from profile will be added to make FQDN in CN.|
|revoke_on_delete|bool|No|Should operator revoke certificate upon CRD deletion?|
|ttl|int64|No|Certificate TTL in hours|
|max_ttl|bool|No|Should we use maximum TTL possible with particular CA? It will check CA TTL and adjust certificate TTL to match it|
|intermediate_ca|bool|No|Is this an intermediate CA certificate?|
|intermediate_ca_priv_key_alg|string|No|Which algorithm to use for Intermediate CA private Key, possible values are: `rsa2048`,`rsa4096`,`ec-Prime256-1`|
|ca_cert_key_name|string|No|Key name in resulting K8S secret, where CA key will be kept.|
|cert_key_name|string|Yes|Key name in resulting K8S secret, where Certificate will be kept.|
|private_key_name|string|Yes|Key name in resulting K8S secret, where Private Key will be kept.|

## PKIProfile
<a name="PKIProfile"></a>
Profile in Vault which keeps PKI settings. Profiles are kept in Vault at path `secret/vault-secrets-operator/profiles/`

Each profile is a secret, which has data in it, example: profile `linkerd`, then secret will be `secret/vault-secrets-operator/profiles/linkerd`

Profile secret must have such keys with values:
1. `pki_path` - Path in Vault to PKI
2. `domain` - Domain name to add to Certificate
3. `default_ttl` - Default TTL for certs in Hours
4. `pki_role` - Role which to use for Cert issuing
5. `pki_cache_path` - Path to cache in Vault to store TLS certs. Need to be added to operator default Path
