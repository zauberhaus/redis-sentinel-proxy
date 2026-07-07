package masterresolver

import (
	"context"
	"time"
)

// SetSentinelNotReadyBackoff shortens the wait between resolve attempts while
// sentinel reports the startup placeholder, so tests don't sleep for real.
// It returns a function restoring the previous value.
func SetSentinelNotReadyBackoff(d time.Duration) (restore func()) {
	old := sentinelNotReadyBackoff
	sentinelNotReadyBackoff = d
	return func() { sentinelNotReadyBackoff = old }
}

// InitialResolve exposes initialMasterAddressResolve so tests can complete
// the startup resolve without running the full update loop (whose shutdown
// closes the sentinel client).
func (r *RedisMasterResolver) InitialResolve(ctx context.Context) error {
	return r.initialMasterAddressResolve(ctx)
}
