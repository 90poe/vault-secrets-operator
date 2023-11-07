package healthchecker_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/90poe/vault-secrets-operator/internal/healthchecker"
	"github.com/stretchr/testify/require"
)

func TestChecker(t *testing.T) {
	t.Parallel()
	resp, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, "/healthz", nil)
	require.NoError(t, err)
	// good case
	err = healthchecker.OperatorHealthChecker(resp)
	require.NoError(t, err)
	// error case
	errSent := fmt.Errorf("test error")
	healthchecker.SetOperatorStatusError(errSent)
	err = healthchecker.OperatorHealthChecker(resp)
	require.ErrorContains(t, err, errSent.Error())
}
