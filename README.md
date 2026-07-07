# redis-sentinel-proxy

A small TCP proxy that keeps pointing at the current Redis master in a
Sentinel-managed setup.

It asks a Redis Sentinel for the address of the master named `-master`,
verifies that the resolved node actually reports `role:master` (Sentinel's
view can be briefly stale during a failover), and forwards every TCP
connection it accepts on `-listen` to that address. Clients connect to one
stable address and never need to speak the Sentinel protocol themselves.

In particular, this solves the problem of accessing a Sentinel-managed Redis
running in Kubernetes: Sentinel announces the master by its in-cluster pod or
service address, which clients outside the cluster can neither resolve nor
reach — and many clients don't support the Sentinel protocol in the first
place. Deployed inside the cluster and exposed via a Service or Ingress, the
proxy gives such clients a single stable endpoint that always leads to the
current master, across failovers, without them needing any Sentinel awareness
or access to the pod network.

## Features

- Continuous master resolution via Sentinel, with a `ROLE` check so traffic is
  never sent to a stale master during failover
- Sentinel authentication (`SENTINEL_PASSWORD` / `-password`)
- TLS everywhere it matters: towards Sentinel, towards the master (originated
  or end-to-end pass-through), and terminated for clients — each with optional
  mutual TLS
- Resource limits: connection cap and idle timeout
- Configurable via CLI flags, environment variables, or a YAML file
- Static binaries and multi-arch Docker images

## Limitations

The proxy forwards **all** traffic to the current master — replicas are never
used, not even for reads. Through the proxy the Redis setup therefore behaves
as active/passive: one node serves the entire load while the replicas exist
only as failover standbys. Sentinel-aware clients that spread reads across
replicas only work from inside the Kubernetes cluster, where the replica
addresses are reachable — for outside clients going through the proxy, read
scaling is not possible.

## Quick start

```
./redis-sentinel-proxy -listen :9999 -sentinel sentinel.example.com:26379 -master mymaster
```

Clients then connect to `:9999` as if it were the Redis master.

## Configuration

Every option can be set as a CLI flag, an environment variable, or a key in a
YAML file passed with `-config FILE`. Precedence:

**CLI flag > environment variable > config file > built-in default**

| Flag | Environment variable | YAML key | Default | Meaning |
| --- | --- | --- | --- | --- |
| `-listen` | `RSP_LISTEN` | `listen` | `:9999` | Local address to accept client connections on |
| `-sentinel` | `RSP_SENTINEL` | `sentinel` | `:26379` | Sentinel address |
| `-master` | `RSP_MASTER` | `master_group` | `mymaster` | Name of the master group to resolve |
| `-password` | `SENTINEL_PASSWORD` | `password` | — | Password for Sentinel; also used for the master-role probe unless `-master-password` is set |
| `-master-password` | `RSP_MASTER_PASSWORD` | `master_password` | — | Password for the master-role probe when the master's password differs from Sentinel's; set explicitly empty to probe without `AUTH` (Sentinel has a password, master doesn't) |
| `-resolve-retries` | `RSP_RESOLVE_RETRIES` | `resolve_retries` | `3` | Consecutive retries of the initial master resolve |
| `-max-connections` | `RSP_MAX_CONNECTIONS` | `max_connections` | `100` | Cap on concurrently proxied client connections (0 = unlimited) |
| `-idle-timeout` | `RSP_IDLE_TIMEOUT` | `idle_timeout` | `30s` | Close a connection after no traffic in either direction for this long (0 = never) |
| `-debug` | `RSP_DEBUG` | `debug` | `false` | Per-connection debug logging (lifecycle and byte counts, not payloads) |

Notes:

- Prefer `SENTINEL_PASSWORD` over `-password` — flags are visible in `ps`.
- A connection with traffic in only one direction (e.g. a pub/sub subscriber)
  is not considered idle.
- Further clients beyond `-max-connections` are rejected immediately.

### TLS to Sentinel

The proxied connection to the master is unaffected by these options.

| Flag | Environment variable | YAML key (`sentinel_tls:`) | Meaning |
| --- | --- | --- | --- |
| `-sentinel-tls` | `RSP_SENTINEL_TLS` | `enabled` | Connect to Sentinel over TLS |
| `-sentinel-tls-ca-file` | `RSP_SENTINEL_TLS_CA_FILE` | `ca_file` | PEM file with CA certificates to verify the Sentinel certificate (default: system roots) |
| `-sentinel-tls-cert-file` | `RSP_SENTINEL_TLS_CERT_FILE` | `cert_file` | Client certificate for mutual TLS |
| `-sentinel-tls-key-file` | `RSP_SENTINEL_TLS_KEY_FILE` | `key_file` | Client certificate key for mutual TLS |
| `-sentinel-tls-server-name` | `RSP_SENTINEL_TLS_SERVER_NAME` | `server_name` | Server name for certificate verification (default: host from `-sentinel`) |
| `-sentinel-tls-skip-verify` | `RSP_SENTINEL_TLS_SKIP_VERIFY` | `skip_verify` | Skip certificate verification (insecure, testing only) |

### TLS for clients

The proxy terminates TLS on the listen address and forwards plain TCP (or
TLS, see below) to the master.

| Flag | Environment variable | YAML key (`listen_tls:`) | Meaning |
| --- | --- | --- | --- |
| `-listen-tls` | `RSP_LISTEN_TLS` | `enabled` | Serve TLS to clients on the listen address |
| `-listen-tls-cert-file` | `RSP_LISTEN_TLS_CERT_FILE` | `cert_file` | Server certificate (required with `-listen-tls`) |
| `-listen-tls-key-file` | `RSP_LISTEN_TLS_KEY_FILE` | `key_file` | Server certificate key (required with `-listen-tls`) |
| `-listen-tls-client-ca-file` | `RSP_LISTEN_TLS_CLIENT_CA_FILE` | `client_ca_file` | When set, clients must present a certificate signed by one of these CAs (mutual TLS) |

### TLS to the master

Three modes:

1. **Plain pass-through (default).** The proxy pipes raw bytes. A TLS-only
   master still works without any of these options: clients do the TLS
   handshake end-to-end with the master through the proxy. Make sure clients
   verify the master's certificate (via its SANs or an overridden server
   name).
2. **Originated TLS.** Set any `-master-tls-*` option (each implies
   `-master-tls`) and the proxy opens its own TLS connection to the master.
   Use this when the proxy terminates client TLS (`-listen-tls`) or clients
   speak plaintext but the master requires TLS.
3. **Declared pass-through (`-master-tls-passthrough`).** Like mode 1 for
   client traffic, but tells the proxy the master speaks TLS so the
   master-role probe uses the `-master-tls-*` settings. Mutually exclusive
   with `-master-tls`. Please make sure to enable TLS-passthrough when using a Traefik IngressRouteTCP.

| Flag | Environment variable | YAML key (`master_tls:`) | Meaning |
| --- | --- | --- | --- |
| `-master-tls` | `RSP_MASTER_TLS` | `enabled` | Originate TLS towards the master |
| `-master-tls-ca-file` | `RSP_MASTER_TLS_CA_FILE` | `ca_file` | PEM file with CA certificates to verify the master certificate (default: system roots) |
| `-master-tls-cert-file` | `RSP_MASTER_TLS_CERT_FILE` | `cert_file` | Client certificate for mutual TLS |
| `-master-tls-key-file` | `RSP_MASTER_TLS_KEY_FILE` | `key_file` | Client certificate key for mutual TLS |
| `-master-tls-server-name` | `RSP_MASTER_TLS_SERVER_NAME` | `server_name` | Server name for certificate verification (default: the address resolved via Sentinel, usually an IP — so either the certificate needs a matching IP SAN or set this) |
| `-master-tls-skip-verify` | `RSP_MASTER_TLS_SKIP_VERIFY` | `skip_verify` | Skip certificate verification (insecure, testing only) |
| `-master-tls-passthrough` | `RSP_MASTER_TLS_PASSTHROUGH` | `passthrough` | Master speaks TLS but client bytes are passed through untouched |

### Config file example

Any option (the password included) can be set via YAML:

```yaml
listen: ":9999"
sentinel: "sentinel.example.com:26379"
master_group: mymaster
password: secret
resolve_retries: 10
max_connections: 500
idle_timeout: 5m

sentinel_tls:
  enabled: true
  ca_file: /etc/redis-sentinel-proxy/ca.pem
  server_name: sentinel.example.com

listen_tls:
  enabled: true
  cert_file: /etc/redis-sentinel-proxy/cert.pem
  key_file: /etc/redis-sentinel-proxy/key.pem
  client_ca_file: /etc/redis-sentinel-proxy/client-ca.pem

master_tls:
  ca_file: /etc/redis-sentinel-proxy/master-ca.pem
  server_name: redis.example.com
```

```
./redis-sentinel-proxy -config /etc/redis-sentinel-proxy/config.yaml
```

## Security notes

The proxy is an unauthenticated TCP forwarder: anyone who can reach the
listen port effectively reaches the Redis master. On untrusted networks:

- Require client certificates with `-listen-tls` + `-listen-tls-client-ca-file`.
  The proxy completes the client's TLS handshake **before** opening a
  connection to the master, so unauthenticated clients cannot consume master
  connections.
- Enable `-sentinel-tls` with a CA — with plaintext Sentinel, a spoofed
  Sentinel reply can redirect all client traffic to an attacker-chosen
  address.
- Set `-max-connections` and `-idle-timeout` to bound resource usage.
- Keep the config file readable only by the service user (`chmod 0600`) when
  it contains a password, and prefer `SENTINEL_PASSWORD` over `-password`.

## Building

Requires Go 1.26+.

- `go build .` — plain local build.
- `./scripts/build.sh` — static binary (`CGO_ENABLED=0`, stripped), same
  build the `Dockerfile` uses.
- `./scripts/build_dist.sh` — cross-compiles static binaries for every
  supported OS/arch into `./dist`, embedding version info (`git describe`,
  commit, build time) via `-ldflags`. Override the platform list with
  `PLATFORM="linux/amd64 linux/arm64"` and the version with `VERSION=v1.2.3`.

## Docker

Two Dockerfiles are provided:

- `Dockerfile` — builds the binary from source inside the image (single
  architecture, matches the host running `docker build`). Good for local
  development:

  ```
  docker build -t redis-sentinel-proxy .
  docker run --rm -p 9999:9999 redis-sentinel-proxy -sentinel sentinel.example.com:26379 -master mymaster
  ```

- `Dockerfile.prod` — packages a pre-built binary from `./dist` (see
  `build_dist.sh` above) and picks the right one for the target architecture
  at image-build time via `scripts/detect.sh`. This is what
  `scripts/deploy_dist.sh` uses to publish multi-arch images.

### Building and pushing a multi-arch image

`scripts/deploy_dist.sh` cross-compiles the binaries (calling `build_dist.sh`
for you) and then builds and pushes a multi-arch image with `docker buildx`:

```
docker login                 # authenticate with the target registry first
./scripts/deploy_dist.sh
```

It tags the image as `$IMAGE:$VERSION`, additionally tagging `$IMAGE:latest`
when `$VERSION` is a clean (non-dirty) tag. Configurable via environment
variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `IMAGE` | `<owner>/<repo>` parsed from the git remote | Image name to tag/push, e.g. `ghcr.io/you/redis-sentinel-proxy` |
| `VERSION` | `git describe --tags --always --dirty` | Image tag |
| `PLATFORM` | `linux/amd64 linux/arm64 linux/ppc64le linux/riscv64` | Space-separated target platforms |
| `PUSH` | `true` | Set to `false` to build without pushing (`--output type=cacheonly`) |
| `BUILDER` | `<repo>-deploy` | Name of the `docker buildx` builder instance to create/use |

## Testing

```
go test ./...
```

No external services needed — Sentinel, TLS, and network behavior are
exercised with in-process mocks.

## License and credits

Apache License 2.0 — see [LICENSE.txt](LICENSE.txt).

Based on code from [redis-sentinel-proxy](https://github.com/enriclluelles/redis-sentinel-proxy)
by Enric Lluelles, originally released under the MIT license; its notice is
preserved in [NOTICE](NOTICE).