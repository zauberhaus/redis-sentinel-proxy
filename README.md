# redis-sentinel-proxy

A small TCP proxy that keeps pointing at the current Redis master in a
Sentinel-managed setup.

> [!WARNING]
> This project is in **alpha** status and not ready for production use. Its
> main purpose is to access a Sentinel-managed Redis cluster from outside,
> e.g. with [Redis Insight](https://redis.io/insight/).

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
- On-demand re-resolve: when connecting to the master or a replica fails, the
  proxy immediately refreshes the addresses via Sentinel and retries once,
  instead of dropping the client until the next periodic resolve
- Survives master restarts: a disappearing DNS record (a pod behind a
  headless service that is restarting) or Sentinel's startup placeholder is
  waited out without limit; other resolve failures retry with a progressive
  backoff (1s doubling up to 30s) and only terminate the proxy once
  `-resolve-retries` consecutive attempts have failed
- Optional read-only endpoint (`-replica-listen`) that spreads client
  connections across all healthy replicas for read scaling
- Optional per-command routing (`-router`): the master endpoint parses the
  Redis protocol and sends read commands to a replica and everything else to
  the master, so a single client connection gets read scaling transparently
- Sentinel authentication (`SENTINEL_PASSWORD` / `-password`)
- TLS everywhere it matters: towards Sentinel, towards the master (originated
  or end-to-end pass-through), and terminated for clients — each with optional
  mutual TLS
- Resource limits: connection cap and idle timeout
- Configurable via CLI flags, environment variables, or a YAML file
- Static binaries and multi-arch Docker images

## Limitations

The master endpoint forwards **all** its traffic to the current master, so
with only that endpoint the Redis setup behaves as active/passive: one node
serves the entire load while the replicas exist only as failover standbys.
Enabling the read-only endpoint (`-replica-listen`) lifts this for reads: it
load-balances connections across all healthy replicas, giving outside clients
read scaling without any Sentinel awareness.

By default the split is per **connection**, not per command: the proxy never
inspects the proxied traffic, so applications must use two connection pools
and keep writes on the master endpoint themselves (a write sent to the
replica endpoint is rejected by Redis with a `READONLY` error). Enabling
`-router` lifts this: the master endpoint then parses the Redis protocol and
routes each command individually — see
[Per-command routing](#per-command-routing--router).

## Quick start

```
./redis-sentinel-proxy -listen :6379 -sentinel sentinel.example.com:26379 -master mymaster
```

Clients then connect to `:6379` as if it were the Redis master.

## Configuration

Every option can be set as a CLI flag, an environment variable, or a key in a
YAML file passed with `-config FILE`. Precedence:

**CLI flag > environment variable > config file > built-in default**

| Flag | Environment variable | YAML key | Default | Meaning |
| --- | --- | --- | --- | --- |
| `-listen` | `RSP_LISTEN` | `listen` | `:10000` | Local address of the master endpoint (empty with `-replica-listen` set = disabled, replica-only proxy) |
| `-replica-listen` | `RSP_REPLICA_LISTEN` | `replica_listen` | — | Local address of the read-only endpoint that load-balances across replicas (empty = disabled) |
| `-replica-fallback` | `RSP_REPLICA_FALLBACK` | `replica_fallback` | `master` | While no healthy replica is known: `master` proxies read connections to the master, `reject` refuses them |
| `-router` | `RSP_ROUTER` | `router` | `false` | Parse the Redis protocol on the master endpoint and route each command by type: reads go to a healthy replica, writes and unknown commands to the master |
| `-sentinel` | `RSP_SENTINEL` | `sentinel` | `:26379` | Sentinel address |
| `-master` | `RSP_MASTER` | `master_group` | `mymaster` | Name of the master group to resolve |
| `-username` | `SENTINEL_USERNAME` | `username` | — | ACL username for Sentinel; empty means authenticating with the password alone (`requirepass`) |
| `-password` | `SENTINEL_PASSWORD` | `password` | — | Password for Sentinel; also used for the master-role probe unless `-master-password` is set |
| `-master-username` | `RSP_MASTER_USERNAME` | `master_username` | — | ACL username for the master-role probe when it differs from Sentinel's (unset = use the Sentinel username) |
| `-master-password` | `RSP_MASTER_PASSWORD` | `master_password` | — | Password for the master-role probe when the master's password differs from Sentinel's; set explicitly empty to probe without `AUTH` (Sentinel has a password, master doesn't) |
| `-resolve-retries` | `RSP_RESOLVE_RETRIES` | `resolve_retries` | `3` | Consecutive failures of the master resolve to tolerate before the proxy exits, with a progressive backoff between attempts (1s doubling up to 30s); the last known master keeps being served in the meantime |
| `-max-connections` | `RSP_MAX_CONNECTIONS` | `max_connections` | `100` | Cap on concurrently proxied client connections (0 = unlimited) |
| `-idle-timeout` | `RSP_IDLE_TIMEOUT` | `idle_timeout` | `30s` | Close a connection after no traffic in either direction for this long (0 = never) |
| `-debug` | `RSP_DEBUG` | `debug` | `false` | Per-connection debug logging (lifecycle and byte counts, not payloads); master/replica address changes are always logged |

Notes:

- Prefer `SENTINEL_PASSWORD` over `-password` — flags are visible in `ps`.
- A connection with traffic in only one direction (e.g. a pub/sub subscriber)
  is not considered idle.
- Further clients beyond `-max-connections` are rejected immediately.
  The limit is shared between the master and replica endpoints.

### Read-only replica endpoint

With `-replica-listen` set, the proxy serves a second endpoint that
load-balances client connections round-robin across all healthy replicas of
the master group. Replicas are discovered via `SENTINEL replicas` (Redis 5+)
alongside every master resolve; a replica counts as healthy when sentinel
doesn't flag it down or disconnected, its replication link is up, and it
answers a `ROLE` probe with `slave` (the probe uses the same TLS settings and
password as the master probe). The choice is made per connection — an
established connection stays on its replica.

While no healthy replica is known, `-replica-fallback` decides what happens
to new read connections: `master` (default) proxies them to the master, so
the read endpoint never goes dark; `reject` refuses them, so readers can't
silently add load to the master.

The replica endpoint uses the same client-facing TLS settings (`-listen-tls-*`)
as the master endpoint.

Setting `-replica-listen` while leaving `-listen` unset (or empty) disables
the master endpoint entirely, turning the proxy into a read-only, replica-only
endpoint.

### Per-command routing (`-router`)

With `-router` set, the master endpoint stops being a transparent pipe and
parses the RESP protocol instead. Every client connection gets a connection
to the current master and — when a healthy replica is known — one to a
replica (chosen round-robin, discovered via Sentinel like for
`-replica-listen`). Each command is then routed by its type:

- **Read-only commands** (`GET`, `MGET`, `HGETALL`, `SCAN`, `FT.SEARCH`,
  `JSON.GET`, `TS.RANGE`, … including the Redis Stack module commands) are
  served by the replica.
- **Writes, admin commands, and anything unknown** go to the master — the
  safe default, so new or unrecognized commands are never sent to a replica.
- Commands that only *may* write (`SORT`, `GEORADIUS`, `EVAL`, `BITFIELD`,
  `GETEX`, `XREADGROUP`, …) go to the master; their read-only variants
  (`SORT_RO`, `EVAL_RO`, `BITFIELD_RO`, …) stay on the replica.
- **Connection state** (`AUTH`, `HELLO`, `SELECT`, `RESET`, `CLIENT`) is
  forwarded to both backends so they stay in sync; the client sees the
  master's reply.
- **Subscriptions, transactions, and monitoring** (`SUBSCRIBE`, `PSUBSCRIBE`,
  `SSUBSCRIBE`, `MULTI`, `WATCH`, `MONITOR`, and the unsubscribe commands)
  pin the connection to the master for its remaining lifetime; from then on
  it behaves like a plain proxied connection. The same happens for clients
  using the inline (telnet-style) protocol.

When no healthy replica is known or the replica connection cannot be
established, the session degrades gracefully: reads are served by the master,
which is always correct.

Caveats:

- Replicas are eventually consistent — a read routed to a replica may not yet
  see an immediately preceding write (`WAIT` can be used to bound this).
- Commands are relayed strictly in order per connection, so a blocking read
  (e.g. `XREAD BLOCK`) stalls pipelined commands queued behind it.
- Client-side caching (`CLIENT TRACKING`) is not supported in router mode:
  invalidation messages are only relayed from the master connection.
- `-router` requires the plain master endpoint and cannot be combined with
  `-master-tls-passthrough`, because the proxy must be able to read the
  protocol (terminating client TLS with `-listen-tls-*` and originating
  backend TLS with `-master-tls` both work fine).
- The `-replica-fallback` setting only applies to the `-replica-listen`
  endpoint; router mode always falls back to the master.

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
replica_listen: ":9998"
replica_fallback: master
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