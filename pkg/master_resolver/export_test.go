package masterresolver

import "time"

// SetSentinelNotReadyBackoff shortens the wait between resolve attempts while
// sentinel reports the startup placeholder, so tests don't sleep for real.
// It returns a function restoring the previous value.
func SetSentinelNotReadyBackoff(d time.Duration) (restore func()) {
	old := sentinelNotReadyBackoff
	sentinelNotReadyBackoff = d
	return func() { sentinelNotReadyBackoff = old }
}
