package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// FromEnv reads the settings from environment variables, returning a Config
// containing only the variables that are actually set.
func FromEnv() (*Config, error) {
	c := &Config{
		SentinelTLS: &BackendTLS{},
		ListenTLS:   &ListenTLS{},
		MasterTLS:   &BackendTLS{},
	}

	strEnv(&c.Listen, "RSP_LISTEN")
	strEnv(&c.ReplicaListen, "RSP_REPLICA_LISTEN")
	strEnv(&c.ReplicaFallback, "RSP_REPLICA_FALLBACK")
	strEnv(&c.Sentinel, "RSP_SENTINEL")
	strEnv(&c.Master, "RSP_MASTER")
	strEnv(&c.Username, "SENTINEL_USERNAME")
	strEnv(&c.Password, "SENTINEL_PASSWORD")
	strEnv(&c.MasterUsername, "RSP_MASTER_USERNAME")
	strEnv(&c.MasterPassword, "RSP_MASTER_PASSWORD")
	if err := intEnv(&c.ResolveRetries, "RSP_RESOLVE_RETRIES"); err != nil {
		return nil, err
	}
	if err := intEnv(&c.MaxConnections, "RSP_MAX_CONNECTIONS"); err != nil {
		return nil, err
	}
	if err := durEnv(&c.IdleTimeout, "RSP_IDLE_TIMEOUT"); err != nil {
		return nil, err
	}
	if err := boolEnv(&c.Debug, "RSP_DEBUG"); err != nil {
		return nil, err
	}

	if err := boolEnv(&c.SentinelTLS.Enabled, "RSP_SENTINEL_TLS"); err != nil {
		return nil, err
	}
	strEnv(&c.SentinelTLS.CAFile, "RSP_SENTINEL_TLS_CA_FILE")
	strEnv(&c.SentinelTLS.CertFile, "RSP_SENTINEL_TLS_CERT_FILE")
	strEnv(&c.SentinelTLS.KeyFile, "RSP_SENTINEL_TLS_KEY_FILE")
	strEnv(&c.SentinelTLS.ServerName, "RSP_SENTINEL_TLS_SERVER_NAME")
	if err := boolEnv(&c.SentinelTLS.SkipVerify, "RSP_SENTINEL_TLS_SKIP_VERIFY"); err != nil {
		return nil, err
	}

	if err := boolEnv(&c.ListenTLS.Enabled, "RSP_LISTEN_TLS"); err != nil {
		return nil, err
	}
	strEnv(&c.ListenTLS.CertFile, "RSP_LISTEN_TLS_CERT_FILE")
	strEnv(&c.ListenTLS.KeyFile, "RSP_LISTEN_TLS_KEY_FILE")
	strEnv(&c.ListenTLS.ClientCAFile, "RSP_LISTEN_TLS_CLIENT_CA_FILE")

	if err := boolEnv(&c.MasterTLS.Enabled, "RSP_MASTER_TLS"); err != nil {
		return nil, err
	}
	strEnv(&c.MasterTLS.CAFile, "RSP_MASTER_TLS_CA_FILE")
	strEnv(&c.MasterTLS.CertFile, "RSP_MASTER_TLS_CERT_FILE")
	strEnv(&c.MasterTLS.KeyFile, "RSP_MASTER_TLS_KEY_FILE")
	strEnv(&c.MasterTLS.ServerName, "RSP_MASTER_TLS_SERVER_NAME")
	if err := boolEnv(&c.MasterTLS.SkipVerify, "RSP_MASTER_TLS_SKIP_VERIFY"); err != nil {
		return nil, err
	}
	if err := boolEnv(&c.MasterTLS.Passthrough, "RSP_MASTER_TLS_PASSTHROUGH"); err != nil {
		return nil, err
	}

	return c, nil
}

func strEnv(dst **string, name string) {
	if val, ok := os.LookupEnv(name); ok {
		*dst = &val
	}
}

func boolEnv(dst **bool, name string) error {
	val, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return fmt.Errorf("invalid value for %s: %w", name, err)
	}
	*dst = &b
	return nil
}

func durEnv(dst **Duration, name string) error {
	val, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	d, err := time.ParseDuration(val)
	if err != nil {
		return fmt.Errorf("invalid value for %s: %w", name, err)
	}
	*dst = (*Duration)(&d)
	return nil
}

func intEnv(dst **int, name string) error {
	val, ok := os.LookupEnv(name)
	if !ok {
		return nil
	}
	i, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("invalid value for %s: %w", name, err)
	}
	*dst = &i
	return nil
}
