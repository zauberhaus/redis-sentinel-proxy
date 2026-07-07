package config

import (
	"flag"
	"time"
)

// BindFlags registers every option as a flag on fs, using the built-in
// defaults for the help text. The returned function must be called after
// fs.Parse and yields a Config containing only the flags that were set
// explicitly on the command line, so it can head a Merge chain where flags
// take precedence over every other source.
func BindFlags(fs *flag.FlagSet) func() *Config {
	def := Default()

	// assign maps a flag name to a closure that copies the parsed value
	// into a Config; only visited (explicitly set) flags are copied.
	assign := map[string]func(*Config){}

	strFlag := func(name, defVal, usage string, set func(*Config, *string)) {
		p := new(defVal)
		fs.StringVar(p, name, defVal, usage)
		assign[name] = func(c *Config) { set(c, p) }
	}
	boolFlag := func(name string, defVal bool, usage string, set func(*Config, *bool)) {
		p := new(defVal)
		fs.BoolVar(p, name, defVal, usage)
		assign[name] = func(c *Config) { set(c, p) }
	}
	intFlag := func(name string, defVal int, usage string, set func(*Config, *int)) {
		p := new(defVal)
		fs.IntVar(p, name, defVal, usage)
		assign[name] = func(c *Config) { set(c, p) }
	}
	durFlag := func(name string, defVal Duration, usage string, set func(*Config, *Duration)) {
		p := new(time.Duration(defVal))
		fs.DurationVar(p, name, time.Duration(defVal), usage)
		assign[name] = func(c *Config) { set(c, (*Duration)(p)) }
	}

	strFlag("listen", *def.Listen, "local address",
		func(c *Config, v *string) { c.Listen = v })
	strFlag("sentinel", *def.Sentinel, "remote address",
		func(c *Config, v *string) { c.Sentinel = v })
	strFlag("master", *def.Master, "name of the master redis node",
		func(c *Config, v *string) { c.Master = v })
	strFlag("password", "", "redis password",
		func(c *Config, v *string) { c.Password = v })
	strFlag("master-password", "", "password for the master-role probe when it differs from the sentinel password (unset: use the sentinel password; explicitly empty: probe without AUTH)",
		func(c *Config, v *string) { c.MasterPassword = v })
	intFlag("resolve-retries", *def.ResolveRetries, "number of consecutive retries of the redis master node resolve",
		func(c *Config, v *int) { c.ResolveRetries = v })
	intFlag("max-connections", *def.MaxConnections, "maximum number of concurrently proxied client connections (0 = unlimited)",
		func(c *Config, v *int) { c.MaxConnections = v })
	durFlag("idle-timeout", *def.IdleTimeout, "close a proxied connection after no traffic in either direction for this duration, e.g. 5m (0 = never)",
		func(c *Config, v *Duration) { c.IdleTimeout = v })
	boolFlag("debug", *def.Debug, "log per-connection debug information about the proxied traffic (lifecycle and byte counts)",
		func(c *Config, v *bool) { c.Debug = v })

	boolFlag("sentinel-tls", false, "connect to sentinel over TLS",
		func(c *Config, v *bool) { c.ensureSentinelTLS().Enabled = v })
	strFlag("sentinel-tls-ca-file", "", "PEM file with CA certificates to verify the sentinel certificate (default: system roots)",
		func(c *Config, v *string) { c.ensureSentinelTLS().CAFile = v })
	strFlag("sentinel-tls-cert-file", "", "PEM file with a client certificate for mutual TLS",
		func(c *Config, v *string) { c.ensureSentinelTLS().CertFile = v })
	strFlag("sentinel-tls-key-file", "", "PEM file with the client certificate key for mutual TLS",
		func(c *Config, v *string) { c.ensureSentinelTLS().KeyFile = v })
	strFlag("sentinel-tls-server-name", "", "server name used to verify the sentinel certificate (default: host from -sentinel)",
		func(c *Config, v *string) { c.ensureSentinelTLS().ServerName = v })
	boolFlag("sentinel-tls-skip-verify", false, "skip verification of the sentinel certificate (insecure)",
		func(c *Config, v *bool) { c.ensureSentinelTLS().SkipVerify = v })

	boolFlag("listen-tls", false, "serve TLS to clients on the listen address",
		func(c *Config, v *bool) { c.ensureListenTLS().Enabled = v })
	strFlag("listen-tls-cert-file", "", "PEM file with the server certificate for the listen address",
		func(c *Config, v *string) { c.ensureListenTLS().CertFile = v })
	strFlag("listen-tls-key-file", "", "PEM file with the server certificate key for the listen address",
		func(c *Config, v *string) { c.ensureListenTLS().KeyFile = v })
	strFlag("listen-tls-client-ca-file", "", "PEM file with CA certificates; when set, clients must present a certificate signed by one of them (mutual TLS)",
		func(c *Config, v *string) { c.ensureListenTLS().ClientCAFile = v })

	boolFlag("master-tls", false, "originate TLS towards the redis master (default: pass bytes through untouched, so clients may do TLS end-to-end themselves)",
		func(c *Config, v *bool) { c.ensureMasterTLS().Enabled = v })
	strFlag("master-tls-ca-file", "", "PEM file with CA certificates to verify the master certificate (default: system roots); implies -master-tls",
		func(c *Config, v *string) { c.ensureMasterTLS().CAFile = v })
	strFlag("master-tls-cert-file", "", "PEM file with a client certificate for mutual TLS with the master; implies -master-tls",
		func(c *Config, v *string) { c.ensureMasterTLS().CertFile = v })
	strFlag("master-tls-key-file", "", "PEM file with the client certificate key for mutual TLS with the master; implies -master-tls",
		func(c *Config, v *string) { c.ensureMasterTLS().KeyFile = v })
	strFlag("master-tls-server-name", "", "server name used to verify the master certificate (default: the address resolved via sentinel, usually an IP); implies -master-tls",
		func(c *Config, v *string) { c.ensureMasterTLS().ServerName = v })
	boolFlag("master-tls-skip-verify", false, "skip verification of the master certificate (insecure); implies -master-tls",
		func(c *Config, v *bool) { c.ensureMasterTLS().SkipVerify = v })
	boolFlag("master-tls-passthrough", false, "the master speaks TLS but client bytes are passed through untouched (clients do TLS end-to-end); the master-role probe uses the -master-tls-* settings; mutually exclusive with -master-tls",
		func(c *Config, v *bool) { c.ensureMasterTLS().Passthrough = v })

	return func() *Config {
		c := &Config{}
		fs.Visit(func(f *flag.Flag) {
			if set, ok := assign[f.Name]; ok {
				set(c)
			}
		})
		return c
	}
}
