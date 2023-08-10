# VaultCertificate CRD

Example:
```
apiVersion: xo.90poe.io/v1alpha1
kind: VaultCertificate
metadata:
  labels:
    app.kubernetes.io/name: vaultcertificate
    app.kubernetes.io/instance: vaultcertificate-sample
    app.kubernetes.io/part-of: vault-secrets-operator
    app.kubernetes.io/managed-by: kustomize
    app.kubernetes.io/created-by: vault-secrets-operator
  name: vaultcertificate-sample
spec:
  name: vcert-sec
  vault_pki_path: pki-mqtt
  key_type: rsa
  cn: test.example.com
  alt_names: ["*.example.com"]
  cert_ttl: 600
```

## Spec

You will have to amend `spec` section according to your requirements.

Spec section:

|Settings|Type |Required|Notes|
|--------|:---|:------|:---|
|name|string|Yes|Name of Secret in K8S|
|vault_pki_path|string|Yes|Path PKI in Vault.|
|key_type|string|No|Type of private key. Can be: rsa, ec, ecdsa. Default 'rsa'.|
|key_length|uint|No|Keybits lenght of RSA certificate. Default 4096|
|ecdsa_curve|string|No|Curve to use for ECDSA private key. Can be: p224,p256,p384,p521|
|cn|string|Yes|CommonName of the TLS certificate|
|alt_names|[]string|No|Alternative names of the TLS certificate. CN will be included if you don't add it yourself.|
|cert_ttl|int|No|TTL of certificate in seconds. Default: 86400 (24 hour)|
|type|string|Yes|Type of created secret in K8S. Default: kubernetes.io/tls|
