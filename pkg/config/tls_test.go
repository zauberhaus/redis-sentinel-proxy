package config_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

func backendTLS(enabled bool, caFile, certFile, keyFile, serverName string, skipVerify bool) *config.BackendTLS {
	return &config.BackendTLS{
		Enabled:    &enabled,
		CAFile:     &caFile,
		CertFile:   &certFile,
		KeyFile:    &keyFile,
		ServerName: &serverName,
		SkipVerify: &skipVerify,
	}
}

func listenTLS(enabled bool, certFile, keyFile, clientCAFile string) *config.ListenTLS {
	return &config.ListenTLS{
		Enabled:      &enabled,
		CertFile:     &certFile,
		KeyFile:      &keyFile,
		ClientCAFile: &clientCAFile,
	}
}

// loadTLS runs the given TLS sections through config.Load, returning the
// resulting Config so its cached TLS configs can be inspected.
func loadTLS(sentinel, master *config.BackendTLS, listen *config.ListenTLS) (*config.Config, error) {
	return config.Load(&config.Config{
		SentinelTLS: sentinel,
		ListenTLS:   listen,
		MasterTLS:   master,
	}, "")
}

func TestSentinelTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := writeTestKeyPair(t)

	sentinelConf := func(s *config.BackendTLS) (*tls.Config, error) {
		cfg, err := loadTLS(s, nil, nil)
		if err != nil {
			return nil, err
		}
		return cfg.SentinelTLSConfig(), nil
	}

	t.Run("disabled returns nil", func(t *testing.T) {
		conf, err := sentinelConf(backendTLS(false, "", "", "", "", false))
		if err != nil || conf != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", conf, err)
		}
	})

	t.Run("disabled with options errors", func(t *testing.T) {
		if _, err := sentinelConf(backendTLS(false, "ca.pem", "", "", "", false)); err == nil {
			t.Fatal("expected error when TLS options given without -sentinel-tls")
		}
	})

	t.Run("enabled minimal", func(t *testing.T) {
		conf, err := sentinelConf(backendTLS(true, "", "", "", "myserver", true))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.ServerName != "myserver" || !conf.InsecureSkipVerify {
			t.Errorf("conf = %+v, want ServerName=myserver InsecureSkipVerify=true", conf)
		}
	})

	t.Run("enabled with valid CA", func(t *testing.T) {
		conf, err := sentinelConf(backendTLS(true, caFile, "", "", "", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.RootCAs == nil {
			t.Error("RootCAs not set")
		}
	})

	t.Run("enabled with invalid CA file errors", func(t *testing.T) {
		if _, err := sentinelConf(backendTLS(true, "/nonexistent/ca.pem", "", "", "", false)); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("CA file without certificates errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.pem")
		if err := os.WriteFile(path, []byte("not a cert"), 0600); err != nil {
			t.Fatalf("could not write file: %v", err)
		}
		if _, err := sentinelConf(backendTLS(true, path, "", "", "", false)); err == nil {
			t.Fatal("expected error for CA file without certificates")
		}
	})

	t.Run("enabled with valid client cert", func(t *testing.T) {
		conf, err := sentinelConf(backendTLS(true, "", certFile, keyFile, "", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(conf.Certificates) != 1 {
			t.Errorf("Certificates = %v, want 1 entry", conf.Certificates)
		}
	})

	t.Run("cert without key errors", func(t *testing.T) {
		if _, err := sentinelConf(backendTLS(true, "", certFile, "", "", false)); err == nil {
			t.Fatal("expected error when cert given without key")
		}
	})

	t.Run("key without cert errors", func(t *testing.T) {
		if _, err := sentinelConf(backendTLS(true, "", "", keyFile, "", false)); err == nil {
			t.Fatal("expected error when key given without cert")
		}
	})

	t.Run("invalid cert/key pair errors", func(t *testing.T) {
		if _, err := sentinelConf(backendTLS(true, "", certFile, caFile, "", false)); err == nil {
			t.Fatal("expected error for mismatched cert/key pair")
		}
	})
}

func TestListenTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := writeTestKeyPair(t)

	listenConf := func(l *config.ListenTLS) (*tls.Config, error) {
		cfg, err := loadTLS(nil, nil, l)
		if err != nil {
			return nil, err
		}
		return cfg.ListenTLSConfig(), nil
	}

	t.Run("disabled returns nil", func(t *testing.T) {
		conf, err := listenConf(listenTLS(false, "", "", ""))
		if err != nil || conf != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", conf, err)
		}
	})

	t.Run("disabled with options errors", func(t *testing.T) {
		if _, err := listenConf(listenTLS(false, "cert.pem", "", "")); err == nil {
			t.Fatal("expected error when TLS options given without -listen-tls")
		}
	})

	t.Run("enabled without cert errors", func(t *testing.T) {
		if _, err := listenConf(listenTLS(true, "", "", "")); err == nil {
			t.Fatal("expected error when -listen-tls set without cert/key")
		}
	})

	t.Run("enabled with valid cert and key", func(t *testing.T) {
		conf, err := listenConf(listenTLS(true, certFile, keyFile, ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(conf.Certificates) != 1 {
			t.Errorf("Certificates = %v, want 1 entry", conf.Certificates)
		}
		if conf.ClientAuth != tls.NoClientCert {
			t.Errorf("ClientAuth = %v, want NoClientCert", conf.ClientAuth)
		}
	})

	t.Run("enabled with client CA requires client certs", func(t *testing.T) {
		conf, err := listenConf(listenTLS(true, certFile, keyFile, caFile))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", conf.ClientAuth)
		}
		if conf.ClientCAs == nil {
			t.Error("ClientCAs not set")
		}
	})

	t.Run("invalid cert file errors", func(t *testing.T) {
		if _, err := listenConf(listenTLS(true, "/nonexistent/cert.pem", keyFile, "")); err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})

	t.Run("invalid client CA file errors", func(t *testing.T) {
		if _, err := listenConf(listenTLS(true, certFile, keyFile, "/nonexistent/ca.pem")); err == nil {
			t.Fatal("expected error for missing client CA file")
		}
	})
}

func TestMasterTLSConfig(t *testing.T) {
	certFile, keyFile, caFile := writeTestKeyPair(t)

	masterConf := func(m *config.BackendTLS) (*tls.Config, error) {
		cfg, err := loadTLS(nil, m, nil)
		if err != nil {
			return nil, err
		}
		return cfg.MasterTLSConfig(), nil
	}

	t.Run("everything unset returns nil (pass-through)", func(t *testing.T) {
		conf, err := masterConf(backendTLS(false, "", "", "", "", false))
		if err != nil || conf != nil {
			t.Fatalf("got (%v, %v), want (nil, nil)", conf, err)
		}
	})

	t.Run("enabled flag alone", func(t *testing.T) {
		conf, err := masterConf(backendTLS(true, "", "", "", "", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf == nil {
			t.Fatal("conf is nil, want a TLS config")
		}
	})

	t.Run("certificate option implies enabled", func(t *testing.T) {
		conf, err := masterConf(backendTLS(false, caFile, "", "", "", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf == nil || conf.RootCAs == nil {
			t.Fatalf("conf = %+v, want config with RootCAs set", conf)
		}
	})

	t.Run("server name implies enabled", func(t *testing.T) {
		conf, err := masterConf(backendTLS(false, "", "", "", "redis.example.com", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf == nil || conf.ServerName != "redis.example.com" {
			t.Fatalf("conf = %+v, want ServerName=redis.example.com", conf)
		}
	})

	t.Run("skip verify implies enabled", func(t *testing.T) {
		conf, err := masterConf(backendTLS(false, "", "", "", "", true))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conf == nil || !conf.InsecureSkipVerify {
			t.Fatalf("conf = %+v, want InsecureSkipVerify=true", conf)
		}
	})

	t.Run("client certificate for mutual TLS", func(t *testing.T) {
		conf, err := masterConf(backendTLS(false, "", certFile, keyFile, "", false))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(conf.Certificates) != 1 {
			t.Errorf("Certificates = %v, want 1 entry", conf.Certificates)
		}
	})

	t.Run("cert without key errors", func(t *testing.T) {
		if _, err := masterConf(backendTLS(false, "", certFile, "", "", false)); err == nil {
			t.Fatal("expected error when cert given without key")
		}
	})

	t.Run("invalid CA file errors", func(t *testing.T) {
		if _, err := masterConf(backendTLS(true, "/nonexistent/ca.pem", "", "", "", false)); err == nil {
			t.Fatal("expected error for missing CA file")
		}
	})

	t.Run("passthrough gives a probe config but no dial config", func(t *testing.T) {
		m := backendTLS(false, caFile, "", "", "redis.example.com", false)
		m.Passthrough = new(true)

		cfg, err := loadTLS(nil, m, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.MasterTLSConfig() != nil {
			t.Error("MasterTLSConfig() != nil, want nil (proxy must keep passing bytes through)")
		}
		probe := cfg.MasterProbeTLSConfig()
		if probe == nil || probe.RootCAs == nil || probe.ServerName != "redis.example.com" {
			t.Fatalf("MasterProbeTLSConfig() = %+v, want config with RootCAs and ServerName set", probe)
		}
	})

	t.Run("enabled means probe and dial share the config", func(t *testing.T) {
		cfg, err := loadTLS(nil, backendTLS(true, caFile, "", "", "", false), nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.MasterTLSConfig() == nil || cfg.MasterTLSConfig() != cfg.MasterProbeTLSConfig() {
			t.Fatalf("MasterTLSConfig() = %p, MasterProbeTLSConfig() = %p, want the same non-nil config", cfg.MasterTLSConfig(), cfg.MasterProbeTLSConfig())
		}
	})

	t.Run("passthrough with enabled errors", func(t *testing.T) {
		m := backendTLS(true, "", "", "", "", false)
		m.Passthrough = new(true)
		if _, err := loadTLS(nil, m, nil); err == nil {
			t.Fatal("expected error for -master-tls together with -master-tls-passthrough")
		}
	})

	t.Run("passthrough on sentinel errors", func(t *testing.T) {
		s := backendTLS(true, "", "", "", "", false)
		s.Passthrough = new(true)
		if _, err := loadTLS(s, nil, nil); err == nil {
			t.Fatal("expected error for passthrough on sentinel_tls")
		}
	})
}

// writeTestKeyPair writes a self-signed cert/key pair (and a matching CA pool
// file) to a temp dir and returns their paths.
func writeTestKeyPair(t *testing.T) (certFile, keyFile, caFile string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("could not create certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("could not write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("could not write key file: %v", err)
	}
	// The cert file itself is also a valid single-cert CA bundle.
	return certFile, keyFile, certFile
}
