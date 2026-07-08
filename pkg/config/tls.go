package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

func (cs *Config) SentinelTLSConfig() *tls.Config {
	return cs.tls.sentinel
}

func (cs *Config) sentinelTLSConfig() (*tls.Config, error) {
	c := cs.SentinelTLS

	if c != nil && boolSet(c.Passthrough) {
		return nil, errors.New("passthrough is only supported for master_tls")
	}

	if c == nil || c.Enabled == nil || !*c.Enabled {
		if c != nil && (strSet(c.CAFile) || strSet(c.CertFile) || strSet(c.KeyFile) || strSet(c.ServerName) || boolSet(c.SkipVerify)) {
			return nil, errors.New("-sentinel-tls-* options require -sentinel-tls")
		}
		return nil, nil
	}

	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         *c.ServerName,
		InsecureSkipVerify: *c.SkipVerify,
	}

	if c.CAFile != nil && *c.CAFile != "" {
		pool, err := loadCertPool(*c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("sentinel CA: %w", err)
		}
		tlsConf.RootCAs = pool
	}

	if (c.CertFile == nil || *c.CertFile == "") != (c.KeyFile == nil || *c.KeyFile == "") {
		return nil, errors.New("-sentinel-tls-cert-file and -sentinel-tls-key-file must be used together")
	}

	if c.CertFile != nil && *c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(*c.CertFile, *c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading sentinel client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	return tlsConf, nil
}

func (cs *Config) ListenTLSConfig() *tls.Config {
	return cs.tls.listen
}

func (cs *Config) listenTLSConfig() (*tls.Config, error) {
	c := cs.ListenTLS

	if c == nil || c.Enabled == nil || !*c.Enabled {
		if c != nil && (strSet(c.CertFile) || strSet(c.KeyFile) || strSet(c.ClientCAFile)) {
			return nil, errors.New("-listen-tls-* options require -listen-tls")
		}
		return nil, nil
	}

	if (c.CertFile == nil || *c.CertFile == "") || (c.KeyFile == nil || *c.KeyFile == "") {
		return nil, errors.New("-listen-tls requires -listen-tls-cert-file and -listen-tls-key-file")
	}

	cert, err := tls.LoadX509KeyPair(*c.CertFile, *c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading listen server certificate: %w", err)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	if c.ClientCAFile != nil && *c.ClientCAFile != "" {
		pool, err := loadCertPool(*c.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("listen client CA: %w", err)
		}
		tlsConf.ClientCAs = pool
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConf, nil
}

// MasterTLSConfig is the TLS setup for the proxied data connection to the
// master; nil means the proxy pipes client bytes through untouched.
func (cs *Config) MasterTLSConfig() *tls.Config {
	return cs.tls.master
}

// MasterProbeTLSConfig is the TLS setup for the resolver's role probe; in
// passthrough mode it is non-nil while MasterTLSConfig is nil.
func (cs *Config) MasterProbeTLSConfig() *tls.Config {
	return cs.tls.masterProbe
}

// masterTLSConfig returns the TLS configs for the role probe and the proxied
// data connection. In passthrough mode only the probe config is non-nil.
func (cs *Config) masterTLSConfig() (probe *tls.Config, dial *tls.Config, err error) {
	c := cs.MasterTLS

	passthrough := c != nil && boolSet(c.Passthrough)
	if passthrough && boolSet(c.Enabled) {
		return nil, nil, errors.New("-master-tls and -master-tls-passthrough are mutually exclusive")
	}

	// Any -master-tls-* option implies enabled.
	enabled := c != nil && (boolSet(c.Enabled) || strSet(c.CAFile) || strSet(c.CertFile) || strSet(c.KeyFile) || strSet(c.ServerName) || boolSet(c.SkipVerify))
	if !enabled && !passthrough {
		return nil, nil, nil
	}

	tlsConf := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         *c.ServerName,
		InsecureSkipVerify: *c.SkipVerify,
	}

	if c.CAFile != nil && *c.CAFile != "" {
		pool, err := loadCertPool(*c.CAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("master CA: %w", err)
		}
		tlsConf.RootCAs = pool
	}

	if (c.CertFile == nil || *c.CertFile == "") != (c.KeyFile == nil || *c.KeyFile == "") {
		return nil, nil, errors.New("-master-tls-cert-file and -master-tls-key-file must be used together")
	}

	if c.CertFile != nil && *c.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(*c.CertFile, *c.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("loading master client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	if passthrough {
		return tlsConf, nil, nil
	}
	return tlsConf, tlsConf, nil
}

func strSet(s *string) bool { return s != nil && *s != "" }
func boolSet(b *bool) bool  { return b != nil && *b }

func loadCertPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no CA certificates found in %s", caFile)
	}
	return pool, nil
}
