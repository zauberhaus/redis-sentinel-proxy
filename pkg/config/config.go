// cspell:words fiel
package config

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// What the replica listener does while no healthy replica is known.
const (
	ReplicaFallbackMaster = "master"
	ReplicaFallbackReject = "reject"
)

type Config struct {
	Listen          *string     `yaml:"listen,omitempty"`
	ReplicaListen   *string     `yaml:"replica_listen,omitempty"`
	ReplicaFallback *string     `yaml:"replica_fallback,omitempty"`
	Sentinel        *string     `yaml:"sentinel,omitempty"`
	Master          *string     `yaml:"master_group,omitempty"`
	Username        *string     `yaml:"username,omitempty"`
	Password        *string     `yaml:"password,omitempty"`
	MasterUsername  *string     `yaml:"master_username,omitempty"`
	MasterPassword  *string     `yaml:"master_password,omitempty"`
	ResolveRetries  *int        `yaml:"resolve_retries,omitempty"`
	MaxConnections  *int        `yaml:"max_connections,omitempty"`
	IdleTimeout     *Duration   `yaml:"idle_timeout,omitempty"`
	Debug           *bool       `yaml:"debug,omitempty"`
	SentinelTLS     *BackendTLS `yaml:"sentinel_tls,omitempty"`
	ListenTLS       *ListenTLS  `yaml:"listen_tls,omitempty"`
	MasterTLS       *BackendTLS `yaml:"master_tls,omitempty"`

	tls struct {
		master      *tls.Config
		masterProbe *tls.Config
		sentinel    *tls.Config
		listen      *tls.Config
	}
}

type BackendTLS struct {
	Enabled     *bool   `yaml:"enabled,omitempty"`
	CAFile      *string `yaml:"ca_file,omitempty"`
	CertFile    *string `yaml:"cert_file,omitempty"`
	KeyFile     *string `yaml:"key_file,omitempty"`
	ServerName  *string `yaml:"server_name,omitempty"`
	SkipVerify  *bool   `yaml:"skip_verify,omitempty"`
	Passthrough *bool   `yaml:"passthrough,omitempty"`
}

type ListenTLS struct {
	Enabled      *bool   `yaml:"enabled,omitempty"`
	CertFile     *string `yaml:"cert_file,omitempty"`
	KeyFile      *string `yaml:"key_file,omitempty"`
	ClientCAFile *string `yaml:"client_ca_file,omitempty"`
}

// Duration unmarshals from YAML strings like "90s" or "5m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Default returns the built-in defaults; a merge chain ending with Default()
// can be dereferenced without nil checks.
func Default() *Config {
	return &Config{
		Listen:          new(""),
		ReplicaListen:   new(""),
		ReplicaFallback: new(ReplicaFallbackMaster),
		Sentinel:        new(":26379"),
		Master:          new("mymaster"),
		//Password:       new(""),
		ResolveRetries: new(3),
		MaxConnections: new(100),
		IdleTimeout:    new(Duration(30 * time.Second)),
		Debug:          new(false),
		SentinelTLS: &BackendTLS{
			Enabled:    new(false),
			CAFile:     new(""),
			CertFile:   new(""),
			KeyFile:    new(""),
			ServerName: new(""),
			SkipVerify: new(false),
		},
		ListenTLS: &ListenTLS{
			Enabled:      new(false),
			CertFile:     new(""),
			KeyFile:      new(""),
			ClientCAFile: new(""),
		},
		MasterTLS: &BackendTLS{
			Enabled:     new(false),
			CAFile:      new(""),
			CertFile:    new(""),
			KeyFile:     new(""),
			ServerName:  new(""),
			SkipVerify:  new(false),
			Passthrough: new(false),
		},
	}
}

func (c *Config) String() string {
	cfg := struct {
		Config *Config `yaml:"Config"`
	}{new(*c)}

	if c.Password != nil && *c.Password != "" {
		cfg.Config.Password = new("*****")
	}

	if c.MasterPassword != nil && *c.MasterPassword != "" {
		cfg.Config.MasterPassword = new("*****")
	}

	if c.Listen != nil && *c.Listen == "" {
		cfg.Config.Listen = nil
	}

	if c.MasterPassword != nil && *c.MasterPassword != "" {
		cfg.Config.MasterPassword = new("*****")
	}

	if c.ListenTLS != nil && (c.ListenTLS.Enabled == nil || !*c.ListenTLS.Enabled) {
		cfg.Config.ListenTLS = nil
	}

	if c.MasterTLS != nil && (c.MasterTLS.Enabled == nil || !*c.MasterTLS.Enabled) && !boolSet(c.MasterTLS.Passthrough) {
		cfg.Config.MasterTLS = nil
	}

	if c.SentinelTLS != nil && (c.SentinelTLS.Enabled == nil || !*c.SentinelTLS.Enabled) {
		cfg.Config.SentinelTLS = nil
	}

	data, _ := yaml.Marshal(cfg)
	return string(data)
}

// Merge fills every nil field of c from other; merging sources in sequence
// implements precedence (flags, then env, then file, then Default).
func (c *Config) Merge(other *Config) {
	if other == nil {
		return
	}
	fill(&c.Listen, other.Listen)
	fill(&c.ReplicaListen, other.ReplicaListen)
	fill(&c.ReplicaFallback, other.ReplicaFallback)
	fill(&c.Sentinel, other.Sentinel)
	fill(&c.Master, other.Master)
	fill(&c.Username, other.Username)
	fill(&c.Password, other.Password)
	fill(&c.MasterUsername, other.MasterUsername)
	fill(&c.MasterPassword, other.MasterPassword)
	fill(&c.ResolveRetries, other.ResolveRetries)
	fill(&c.MaxConnections, other.MaxConnections)
	fill(&c.IdleTimeout, other.IdleTimeout)
	fill(&c.Debug, other.Debug)

	if o := other.SentinelTLS; o != nil {
		s := c.ensureSentinelTLS()
		fill(&s.Enabled, o.Enabled)
		fill(&s.CAFile, o.CAFile)
		fill(&s.CertFile, o.CertFile)
		fill(&s.KeyFile, o.KeyFile)
		fill(&s.ServerName, o.ServerName)
		fill(&s.SkipVerify, o.SkipVerify)
	}

	if o := other.ListenTLS; o != nil {
		l := c.ensureListenTLS()
		fill(&l.Enabled, o.Enabled)
		fill(&l.CertFile, o.CertFile)
		fill(&l.KeyFile, o.KeyFile)
		fill(&l.ClientCAFile, o.ClientCAFile)
	}

	if o := other.MasterTLS; o != nil {
		m := c.ensureMasterTLS()
		fill(&m.Enabled, o.Enabled)
		fill(&m.CAFile, o.CAFile)
		fill(&m.CertFile, o.CertFile)
		fill(&m.KeyFile, o.KeyFile)
		fill(&m.ServerName, o.ServerName)
		fill(&m.SkipVerify, o.SkipVerify)
		fill(&m.Passthrough, o.Passthrough)
	}
}

func (c *Config) ensureSentinelTLS() *BackendTLS {
	if c.SentinelTLS == nil {
		c.SentinelTLS = &BackendTLS{}
	}
	return c.SentinelTLS
}

func (c *Config) ensureListenTLS() *ListenTLS {
	if c.ListenTLS == nil {
		c.ListenTLS = &ListenTLS{}
	}
	return c.ListenTLS
}

func (c *Config) ensureMasterTLS() *BackendTLS {
	if c.MasterTLS == nil {
		c.MasterTLS = &BackendTLS{}
	}
	return c.MasterTLS
}

func fill[T any](dst **T, src *T) {
	if *dst == nil && src != nil {
		*dst = src
	}
}

func Load(flagCfg *Config, path string) (*Config, error) {
	cfg := flagCfg
	if cfg == nil {
		cfg = &Config{}
	}

	envCfg, err := FromEnv()
	if err != nil {
		return nil, err
	}
	cfg.Merge(envCfg)

	if path != "" {
		fileCfg, err := loadFile(path)
		if err != nil {
			return nil, err
		}
		cfg.Merge(fileCfg)
	}

	cfg.Merge(Default())

	if *cfg.ReplicaFallback != ReplicaFallbackMaster && *cfg.ReplicaFallback != ReplicaFallbackReject {
		return nil, fmt.Errorf("invalid replica_fallback %q (must be %q or %q)",
			*cfg.ReplicaFallback, ReplicaFallbackMaster, ReplicaFallbackReject)
	}

	cfg.tls.sentinel, err = cfg.sentinelTLSConfig()
	if err != nil {
		return nil, err
	}

	cfg.tls.listen, err = cfg.listenTLSConfig()
	if err != nil {
		return nil, err
	}

	cfg.tls.masterProbe, cfg.tls.master, err = cfg.masterTLSConfig()
	if err != nil {
		return nil, err
	}

	if (cfg.Listen == nil || *cfg.Listen == "") && (cfg.ReplicaListen == nil || *cfg.ReplicaListen == "") {
		cfg.Listen = new(":10000")
	}

	if cfg.ReplicaListen != nil && *cfg.ReplicaListen == "" {
		cfg.ReplicaListen = nil
		cfg.ReplicaFallback = nil
	}

	return cfg, nil
}

func loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return &cfg, nil
}
