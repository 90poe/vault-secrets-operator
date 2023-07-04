package vaultclient_test

import (
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	CNname = "test-cert.zodiac.iot.drydock.studio"
)

var log = logf.Log.WithName("testing") // nolint

// Test with real Vault
// func TestSignCertificate(t *testing.T) {
// 	t.Parallel()
// 	os.Setenv("AWS_ACCESS_KEY_ID", "")
// 	os.Setenv("AWS_SECRET_ACCESS_KEY", "")
// 	os.Setenv("AWS_SESSION_TOKEN", "")
// 	ctx, cancelfn := context.WithCancel(context.TODO())
// 	vaultClient, err := vault.New(
// 		"addr",
// 		"role",
// 		true,
// 		vault.ContextWithCancelFN(ctx, cancelfn),
// 		vault.Logger(logTest),
// 	)
// 	require.NoError(t, err)
// 	vaultCl, err := vaultclient.New(
// 		vaultclient.VaultClient(vaultClient),
// 		vaultclient.Logger(log),
// 		vaultclient.ContextWithCancelFN(ctx, cancelfn),
// 		vaultclient.ContextWithCancelFN(ctx, cancelfn),
// 		vaultclient.Logger(logTest),
// 	)
// 	require.NoError(t, err)
// 	testCert, err := certificates.New(CNname, "rsa", 2048,
// 		certificates.AltNames([]string{"*.zodiac.iot.drydock.studio", CNname}),
// 		certificates.ValidUntil(time.Date(2023, 07, 12, 0, 0, 0, 0, time.UTC)))
// 	require.NoError(t, err)
// 	_, err = vaultCl.GetSignedCertificate("pki-mqtt", "vpn", testCert)
// 	require.NoError(t, err)
// 	certOut, err := certificates.GetRawCertificate(testCert.PemCert)
// 	require.NoError(t, err)
// 	assert.Equal(t, certOut.Subject.CommonName, CNname)
// }
