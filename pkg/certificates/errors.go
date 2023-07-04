package certificates

import "fmt"

type (
	CertificateInvalid struct {
		cn string
	}
)

func (c *CertificateInvalid) Error() string {
	return fmt.Sprintf("certificate with CN='%s' is invalid", c.cn)
}
