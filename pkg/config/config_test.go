// cspell:words maste
package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

func TestLoad(t *testing.T) {
	t.Run("full config", func(t *testing.T) {
		// Load eagerly builds the TLS configs, so the file paths must point
		// at real certificates.
		certFile, keyFile, caFile := writeTestKeyPair(t)

		cfg := writeAndLoad(t, fmt.Sprintf(`
listen: ":9999"
replica_listen: ":9998"
replica_fallback: reject
sentinel: "sentinel.example.com:26379"
master_group: mymaster
password: secret
master_password: master-secret
resolve_retries: 5
max_connections: 200
idle_timeout: 5m

sentinel_tls:
  enabled: true
  ca_file: %[1]s
  cert_file: %[2]s
  key_file: %[3]s
  server_name: sentinel.example.com
  skip_verify: false

listen_tls:
  enabled: true
  cert_file: %[2]s
  key_file: %[3]s
  client_ca_file: %[1]s

master_tls:
  enabled: true
  ca_file: %[1]s
  cert_file: %[2]s
  key_file: %[3]s
  server_name: redis.example.com
  skip_verify: false
`, caFile, certFile, keyFile))

		assertStr(t, "listen", cfg.Listen, ":9999")
		assertStr(t, "replica_listen", cfg.ReplicaListen, ":9998")
		assertStr(t, "replica_fallback", cfg.ReplicaFallback, config.ReplicaFallbackReject)
		assertStr(t, "sentinel", cfg.Sentinel, "sentinel.example.com:26379")
		assertStr(t, "master", cfg.Master, "mymaster")
		assertStr(t, "password", cfg.Password, "secret")
		assertStr(t, "master_password", cfg.MasterPassword, "master-secret")
		if cfg.ResolveRetries == nil || *cfg.ResolveRetries != 5 {
			t.Fatalf("resolve_retries = %v, want 5", cfg.ResolveRetries)
		}
		if cfg.MaxConnections == nil || *cfg.MaxConnections != 200 {
			t.Errorf("max_connections = %v, want 200", cfg.MaxConnections)
		}
		if cfg.IdleTimeout == nil || *cfg.IdleTimeout != config.Duration(5*time.Minute) {
			t.Errorf("idle_timeout = %v, want 5m", cfg.IdleTimeout)
		}

		if cfg.SentinelTLS == nil {
			t.Fatal("sentinel_tls is nil")
		}
		assertBool(t, "sentinel_tls.enabled", cfg.SentinelTLS.Enabled, true)
		assertStr(t, "sentinel_tls.ca_file", cfg.SentinelTLS.CAFile, caFile)
		assertBool(t, "sentinel_tls.skip_verify", cfg.SentinelTLS.SkipVerify, false)

		if cfg.ListenTLS == nil {
			t.Fatal("listen_tls is nil")
		}
		assertStr(t, "listen_tls.client_ca_file", cfg.ListenTLS.ClientCAFile, caFile)

		if cfg.MasterTLS == nil {
			t.Fatal("master_tls is nil")
		}
		assertBool(t, "master_tls.enabled", cfg.MasterTLS.Enabled, true)
		assertStr(t, "master_tls.ca_file", cfg.MasterTLS.CAFile, caFile)
		assertStr(t, "master_tls.server_name", cfg.MasterTLS.ServerName, "redis.example.com")
		assertBool(t, "master_tls.skip_verify", cfg.MasterTLS.SkipVerify, false)

		if cfg.SentinelTLSConfig() == nil || cfg.ListenTLSConfig() == nil || cfg.MasterTLSConfig() == nil {
			t.Error("cached TLS configs not built by Load")
		}
	})

	t.Run("partial config is filled with defaults", func(t *testing.T) {
		cfg := writeAndLoad(t, `master_group: file-master`)

		assertStr(t, "master", cfg.Master, "file-master")
		assertStr(t, "listen", cfg.Listen, ":9999")
		assertBool(t, "sentinel_tls.enabled", cfg.SentinelTLS.Enabled, false)
	})

	t.Run("empty file yields the defaults", func(t *testing.T) {
		cfg := writeAndLoad(t, "")
		assertStr(t, "master", cfg.Master, "mymaster")
	})

	t.Run("empty path skips the file", func(t *testing.T) {
		cfg, err := config.Load(nil, "")
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		assertStr(t, "listen", cfg.Listen, ":9999")
	})

	t.Run("flags win over env, env over file, defaults fill the rest", func(t *testing.T) {
		t.Setenv("RSP_SENTINEL", "env-sentinel")
		t.Setenv("RSP_MASTER", "env-master")

		path := filepath.Join(t.TempDir(), "config.yaml")
		writeFile(t, path, "master_group: file-master\npassword: file-password\n")

		flagListen := "flag-listen"
		cfg, err := config.Load(&config.Config{Listen: &flagListen}, path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}

		assertStr(t, "listen", cfg.Listen, "flag-listen")
		assertStr(t, "sentinel", cfg.Sentinel, "env-sentinel")
		assertStr(t, "master", cfg.Master, "env-master")
		assertStr(t, "password", cfg.Password, "file-password")
		if cfg.ResolveRetries == nil || *cfg.ResolveRetries != 3 {
			t.Errorf("resolve_retries = %v, want default 3", cfg.ResolveRetries)
		}
	})

	t.Run("invalid env value errors", func(t *testing.T) {
		t.Setenv("RSP_RESOLVE_RETRIES", "not-an-int")
		if _, err := config.Load(nil, ""); err == nil {
			t.Fatal("expected error for invalid env var")
		}
	})

	t.Run("invalid duration in file errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		writeFile(t, path, "idle_timeout: not-a-duration\n")

		if _, err := config.Load(nil, path); err == nil {
			t.Fatal("expected error for invalid duration, got nil")
		}
	})

	t.Run("invalid replica_fallback errors", func(t *testing.T) {
		if _, err := config.Load(&config.Config{ReplicaFallback: new("bogus")}, ""); err == nil {
			t.Fatal("expected error for invalid replica_fallback, got nil")
		}
	})

	t.Run("unknown field is rejected", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		writeFile(t, path, "maste: mymaster\n")

		if _, err := config.Load(nil, path); err == nil {
			t.Fatal("expected error for unknown field, got nil")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := config.Load(nil, filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})
}

func writeAndLoad(t *testing.T, content string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, content)
	cfg, err := config.Load(nil, path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return cfg
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("could not write %s: %v", path, err)
	}
}

func assertStr(t *testing.T, field string, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is nil, want %q", field, want)
	}
	if *got != want {
		t.Errorf("%s = %q, want %q", field, *got, want)
	}
}

func assertBool(t *testing.T, field string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s is nil, want %v", field, want)
	}
	if *got != want {
		t.Errorf("%s = %v, want %v", field, *got, want)
	}
}
