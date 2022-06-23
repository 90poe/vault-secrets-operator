package consts

const (
	SecManagedByField          = "managed-by"
	SecManagedByValue          = "secretfromvaults-operator.xo.90poe.io"
	OperatorSecretsInVaultPath = "secret/vault-secrets-operator"
	TLSCachePath               = "secret/vault-secrets-operator/tls-cache"
	PKIDomain                  = "domain"
	PKIDefaultTTL              = "default_ttl"
	PKIPath                    = "pki_path"
	PKICachePath               = "pki_cache_path"
	PKIRole                    = "pki_role"
	VaultPKICleanupInHours     = 24
	VaultClientTimeoutSec      = 60
	VaultPlainValueKey         = "value"
	VaultBase64ValueKey        = "base64_value"
	URLCheckRegexpPattern      = `\b(([\w-]+://?|www[.])[^\s()<>]+(?:\([\w\d]+\)|([^[:punct:]\s]|/)))`
	PKIKeyAlgRSA2048           = "rsa2048"
	PKIKeyAlgRSA4096           = "rsa4096"
	PKIKeyAlgECPrime256        = "ec-Prime256-1"
	TLSSerialHumanSeparator    = ":"
	TLSSerialVaultSeparator    = "-"
	SecretsFinalizer           = "finalizer.secretfromvault.xo.90poe.io"
)
