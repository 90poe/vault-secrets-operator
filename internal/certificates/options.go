package certificates

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/90poe/vault-secrets-operator/internal/consts"
)

// Options is a type of options for Certificate
type Options func(*Certificate) error

// ECDSACurve is option function to set Certificate curve for ECDSA type cert
func ECDSACurve(curve string) Options {
	return func(c *Certificate) error {
		curve = strings.ToLower(strings.Trim(curve, " \t"))
		pattern := regexp.MustCompile(consts.ECDSACurvePattern)
		if len(curve) == 0 {
			// Empty string is also valid for EC curve
			return nil
		}
		if !pattern.MatchString(curve) {
			return fmt.Errorf("invalid ECDSA curve, must match pattern `%s`", consts.ECDSACurvePattern)
		}
		c.ECDSACurve = curve
		return nil
	}
}

// AltNames is option to set AltNames
func AltNames(altNames []string) Options {
	return func(c *Certificate) error {
		c.AltNames = append(c.AltNames, altNames...)
		return nil
	}
}

// ValidUntil is option to set AltNames
func ValidUntil(validUntil time.Time) Options {
	return func(c *Certificate) error {
		c.ValidUntil = validUntil
		return nil
	}
}

func New(cn, keyType string, keyBits int, options ...Options) (*Certificate, error) {
	cert := &Certificate{
		CommonName: cn,
		Type:       strings.ToLower(keyType),
		KeyBits:    keyBits,
	}
	for _, option := range options {
		err := option(cert)
		if err != nil {
			return nil, fmt.Errorf("can't make new Certificate object: %w", err)
		}
	}
	// Validate cert type
	pattern := regexp.MustCompile(consts.CertTypePattern)
	if !pattern.MatchString(keyType) {
		return nil, fmt.Errorf("unkown certificate type '%s', must match pattern `%s`", keyType, consts.CertTypePattern)
	}
	// Validate cert key bits
	if cert.Type == CertificateRSA && cert.KeyBits == 0 {
		return nil, fmt.Errorf("for RSA certificate key bits must not be 0")
	}
	return cert, nil
}
