package config_test

import (
	"flag"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

func TestDefault(t *testing.T) {
	cfg := config.Default()

	assertStr(t, "listen", cfg.Listen, "")
	assertStr(t, "sentinel", cfg.Sentinel, ":26379")
	assertStr(t, "master", cfg.Master, "mymaster")
	if cfg.Password != nil {
		t.Errorf("password = %q, want nil (no default password)", *cfg.Password)
	}
	if cfg.ResolveRetries == nil || *cfg.ResolveRetries != 3 {
		t.Errorf("resolve_retries = %v, want 3", cfg.ResolveRetries)
	}
	if cfg.MaxConnections == nil || *cfg.MaxConnections != 100 {
		t.Errorf("max_connections = %v, want 100", cfg.MaxConnections)
	}
	if cfg.IdleTimeout == nil {
		t.Error("idle_timeout is nil, want populated")
	}

	// Every field must be populated so a merged config can be dereferenced
	// without nil checks.
	if cfg.SentinelTLS == nil || cfg.SentinelTLS.Enabled == nil || cfg.SentinelTLS.CAFile == nil ||
		cfg.SentinelTLS.CertFile == nil || cfg.SentinelTLS.KeyFile == nil ||
		cfg.SentinelTLS.ServerName == nil || cfg.SentinelTLS.SkipVerify == nil {
		t.Errorf("sentinel_tls not fully populated: %+v", cfg.SentinelTLS)
	}
	if cfg.ListenTLS == nil || cfg.ListenTLS.Enabled == nil || cfg.ListenTLS.CertFile == nil ||
		cfg.ListenTLS.KeyFile == nil || cfg.ListenTLS.ClientCAFile == nil {
		t.Errorf("listen_tls not fully populated: %+v", cfg.ListenTLS)
	}
	if cfg.MasterTLS == nil || cfg.MasterTLS.Enabled == nil || cfg.MasterTLS.CAFile == nil ||
		cfg.MasterTLS.CertFile == nil || cfg.MasterTLS.KeyFile == nil ||
		cfg.MasterTLS.ServerName == nil || cfg.MasterTLS.SkipVerify == nil {
		t.Errorf("master_tls not fully populated: %+v", cfg.MasterTLS)
	}
}

func TestMerge(t *testing.T) {
	t.Run("set fields win, nil fields are filled", func(t *testing.T) {
		listen := "set-listen"
		enabled := false
		cfg := &config.Config{
			Listen:      &listen,
			SentinelTLS: &config.BackendTLS{Enabled: &enabled},
		}

		otherListen, otherMaster := "other-listen", "other-master"
		otherEnabled := true
		otherCA := "other-ca"
		cfg.Merge(&config.Config{
			Listen:      &otherListen,
			Master:      &otherMaster,
			SentinelTLS: &config.BackendTLS{Enabled: &otherEnabled, CAFile: &otherCA},
		})

		assertStr(t, "listen", cfg.Listen, "set-listen")
		assertStr(t, "master", cfg.Master, "other-master")
		assertBool(t, "sentinel_tls.enabled", cfg.SentinelTLS.Enabled, false)
		assertStr(t, "sentinel_tls.ca_file", cfg.SentinelTLS.CAFile, "other-ca")
	})

	t.Run("nil sections are created on demand", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Merge(config.Default())

		if cfg.MasterTLS == nil {
			t.Fatal("master_tls not created by Merge")
		}
		assertBool(t, "master_tls.enabled", cfg.MasterTLS.Enabled, false)
	})

	t.Run("merging nil is a no-op", func(t *testing.T) {
		listen := "set-listen"
		cfg := &config.Config{Listen: &listen}
		cfg.Merge(nil)
		assertStr(t, "listen", cfg.Listen, "set-listen")
	})
}

func TestFromEnv(t *testing.T) {
	t.Run("only set variables are populated", func(t *testing.T) {
		t.Setenv("RSP_LISTEN", "env-listen")
		t.Setenv("RSP_REPLICA_LISTEN", "env-replica-listen")
		t.Setenv("RSP_REPLICA_FALLBACK", "reject")
		t.Setenv("SENTINEL_USERNAME", "env-username")
		t.Setenv("SENTINEL_PASSWORD", "env-password")
		t.Setenv("RSP_MASTER_USERNAME", "env-master-username")
		t.Setenv("RSP_MASTER_PASSWORD", "env-master-password")
		t.Setenv("RSP_RESOLVE_RETRIES", "5")
		t.Setenv("RSP_MAX_CONNECTIONS", "100")
		t.Setenv("RSP_IDLE_TIMEOUT", "90s")
		t.Setenv("RSP_SENTINEL_TLS", "true")
		t.Setenv("RSP_MASTER_TLS_CA_FILE", "env-master-ca")
		t.Setenv("RSP_MASTER_TLS_SKIP_VERIFY", "true")

		cfg, err := config.FromEnv()
		if err != nil {
			t.Fatalf("FromEnv() error = %v", err)
		}

		assertStr(t, "listen", cfg.Listen, "env-listen")
		assertStr(t, "replica_listen", cfg.ReplicaListen, "env-replica-listen")
		assertStr(t, "replica_fallback", cfg.ReplicaFallback, "reject")
		assertStr(t, "username", cfg.Username, "env-username")
		assertStr(t, "password", cfg.Password, "env-password")
		assertStr(t, "master_username", cfg.MasterUsername, "env-master-username")
		assertStr(t, "master_password", cfg.MasterPassword, "env-master-password")
		if cfg.ResolveRetries == nil || *cfg.ResolveRetries != 5 {
			t.Errorf("resolve_retries = %v, want 5", cfg.ResolveRetries)
		}
		if cfg.MaxConnections == nil || *cfg.MaxConnections != 100 {
			t.Errorf("max_connections = %v, want 100", cfg.MaxConnections)
		}
		if cfg.IdleTimeout == nil || *cfg.IdleTimeout != config.Duration(90*time.Second) {
			t.Errorf("idle_timeout = %v, want 90s", cfg.IdleTimeout)
		}
		assertBool(t, "sentinel_tls.enabled", cfg.SentinelTLS.Enabled, true)
		assertStr(t, "master_tls.ca_file", cfg.MasterTLS.CAFile, "env-master-ca")
		assertBool(t, "master_tls.skip_verify", cfg.MasterTLS.SkipVerify, true)

		if cfg.Sentinel != nil {
			t.Errorf("sentinel = %v, want nil (env var not set)", *cfg.Sentinel)
		}
		if cfg.MasterTLS.Enabled != nil {
			t.Errorf("master_tls.enabled = %v, want nil (env var not set)", *cfg.MasterTLS.Enabled)
		}
	})

	t.Run("invalid bool errors", func(t *testing.T) {
		t.Setenv("RSP_SENTINEL_TLS", "not-a-bool")
		if _, err := config.FromEnv(); err == nil {
			t.Fatal("expected error for invalid bool env var")
		}
	})

	t.Run("invalid int errors", func(t *testing.T) {
		t.Setenv("RSP_RESOLVE_RETRIES", "not-an-int")
		if _, err := config.FromEnv(); err == nil {
			t.Fatal("expected error for invalid int env var")
		}
	})

	t.Run("invalid duration errors", func(t *testing.T) {
		t.Setenv("RSP_IDLE_TIMEOUT", "not-a-duration")
		if _, err := config.FromEnv(); err == nil {
			t.Fatal("expected error for invalid duration env var")
		}
	})
}

func TestBindFlags(t *testing.T) {
	t.Run("only explicitly set flags are returned", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fromFlags := config.BindFlags(fs)

		if err := fs.Parse([]string{"-listen", "flag-listen", "-master-tls-ca-file", "flag-ca", "-sentinel-tls", "-max-connections", "50", "-idle-timeout", "2m", "-username", "flag-username", "-master-password", "flag-master-password", "-master-username", "flag-master-username"}); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		cfg := fromFlags()

		assertStr(t, "listen", cfg.Listen, "flag-listen")
		assertStr(t, "username", cfg.Username, "flag-username")
		assertStr(t, "master_username", cfg.MasterUsername, "flag-master-username")
		assertStr(t, "master_password", cfg.MasterPassword, "flag-master-password")
		assertStr(t, "master_tls.ca_file", cfg.MasterTLS.CAFile, "flag-ca")
		assertBool(t, "sentinel_tls.enabled", cfg.SentinelTLS.Enabled, true)
		if cfg.MaxConnections == nil || *cfg.MaxConnections != 50 {
			t.Errorf("max_connections = %v, want 50", cfg.MaxConnections)
		}
		if cfg.IdleTimeout == nil || *cfg.IdleTimeout != config.Duration(2*time.Minute) {
			t.Errorf("idle_timeout = %v, want 2m", cfg.IdleTimeout)
		}

		if cfg.Sentinel != nil {
			t.Errorf("sentinel = %v, want nil (flag not set)", *cfg.Sentinel)
		}
		if cfg.ListenTLS != nil {
			t.Errorf("listen_tls = %+v, want nil (no flag set)", cfg.ListenTLS)
		}
		if cfg.MasterTLS.Enabled != nil {
			t.Errorf("master_tls.enabled = %v, want nil (flag not set)", *cfg.MasterTLS.Enabled)
		}
	})

	t.Run("no flags set returns empty config", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fromFlags := config.BindFlags(fs)

		if err := fs.Parse(nil); err != nil {
			t.Fatalf("Parse() error = %v", err)
		}
		cfg := fromFlags()

		if cfg.Listen != nil || cfg.SentinelTLS != nil || cfg.ListenTLS != nil || cfg.MasterTLS != nil {
			t.Errorf("cfg = %+v, want all fields nil", cfg)
		}
	})

	t.Run("flag defaults match Default()", func(t *testing.T) {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		config.BindFlags(fs)

		def := config.Default()
		if f := fs.Lookup("listen"); f == nil || f.DefValue != *def.Listen {
			t.Errorf("listen flag default = %v, want %q", f, *def.Listen)
		}
		if f := fs.Lookup("resolve-retries"); f == nil || f.DefValue != "3" {
			t.Errorf("resolve-retries flag default = %v, want 3", f)
		}
	})
}
