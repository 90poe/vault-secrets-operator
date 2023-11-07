package healthchecker

import (
	"net/http"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/healthz"
)

var (
	operatorStatus     error
	operatorStatusSync sync.RWMutex
	// OperatorHealthChecker is a health checker for the operator, which will use operatorStatus to determine the status
	OperatorHealthChecker healthz.Checker = func(_ *http.Request) error {
		operatorStatusSync.RLock()
		defer operatorStatusSync.RUnlock()
		if operatorStatus != nil {
			return operatorStatus
		}
		return nil
	}
)

// SetOperatorStatusError will set the operator status to the given error
func SetOperatorStatusError(status error) {
	operatorStatusSync.Lock()
	defer operatorStatusSync.Unlock()
	operatorStatus = status
}
