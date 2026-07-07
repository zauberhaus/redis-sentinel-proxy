package main

import (
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

func ptr[T any](v T) *T { return &v }

// testConfig resolves a full config for runProxying with the given listen
// and sentinel addresses and no resolve retries, so failures surface fast.
func testConfig(t *testing.T, listen, sentinel string) *config.Config {
	t.Helper()

	cfg, err := config.Load(&config.Config{
		Listen:         ptr(listen),
		Sentinel:       ptr(sentinel),
		ResolveRetries: ptr(0),
	}, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return cfg
}

func TestRunProxyingFailsOnUnresolvableMaster(t *testing.T) {
	// Nothing listens on this port, so the sentinel dial fails fast and
	// runProxying should return the resolver's error without blocking.
	unusedAddr := "127.0.0.1:1" // low port, connection refused immediately
	cfg := testConfig(t, "127.0.0.1:0", unusedAddr)

	done := make(chan error, 1)
	go func() {
		done <- runProxying(cfg)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from runProxying with an unreachable sentinel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runProxying did not return in time")
	}
}

func TestRunProxyingFailsOnInvalidSentinelAddr(t *testing.T) {
	cfg := testConfig(t, "127.0.0.1:0", "not a valid addr")

	done := make(chan error, 1)
	go func() {
		done <- runProxying(cfg)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for an invalid sentinel address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runProxying did not return in time")
	}
}

func TestRunProxyingFailsOnInvalidListenAddr(t *testing.T) {
	cfg := testConfig(t, "not a valid addr", "127.0.0.1:1")

	done := make(chan error, 1)
	go func() {
		done <- runProxying(cfg)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error for an invalid listen address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runProxying did not return in time")
	}
}
