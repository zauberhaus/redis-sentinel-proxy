package masterresolver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

// errSentinelNotReady marks a resolve failure caused by sentinel reporting
// the 0.0.0.0 (or ::) placeholder it monitors right after startup, before
// it's reconfigured with the real master. Unlike other failures this always
// resolves itself once sentinel finishes starting, so the retry loops wait it
// out (with sentinelNotReadyBackoff between attempts) instead of counting it
// against the regular retry budget.
var errSentinelNotReady = errors.New("sentinel is not ready yet")

// sentinelNotReadyBackoff is how long to wait between resolve attempts while
// sentinel is still reporting the startup placeholder (a var so tests can
// shorten it).
var sentinelNotReadyBackoff = 10 * time.Second

type RedisMasterResolver struct {
	masterName               string
	sentinel                 *redis.SentinelClient
	masterTLSConf            *tls.Config
	masterUsername           string
	masterPassword           string
	retryOnMasterResolveFail int
	trackReplicas            bool

	masterAddrLock           *sync.RWMutex
	initialMasterResolveLock chan struct{}

	masterAddr   string
	replicaAddrs []string
	replicaIdx   atomic.Uint64
}

// clientOptions builds the go-redis options shared by the sentinel client
// and the role probes: short per-operation timeouts (the resolve loop runs
// every second), no client-side retries (the loops implement their own retry
// policy), and no CLIENT SETINFO handshake chatter.
func clientOptions(addr string, username, password string, tlsConf *tls.Config) *redis.Options {
	return &redis.Options{
		Addr:            addr,
		Username:        username,
		Password:        password,
		TLSConfig:       tlsConf,
		DialTimeout:     time.Second,
		ReadTimeout:     time.Second,
		WriteTimeout:    time.Second,
		MaxRetries:      -1,
		PoolSize:        1,
		DisableIdentity: true,
	}
}

// NewRedisMasterResolver creates a resolver that queries the sentinel
// configured in cfg. The sentinel connection is pooled and reused across
// resolves; role probes open a short-lived connection to the resolved node.
func NewRedisMasterResolver(cfg *config.Config) *RedisMasterResolver {
	var username string
	if cfg.Username != nil {
		username = *cfg.Username
	}
	var password string
	if cfg.Password != nil {
		password = *cfg.Password
	}

	// The master-role probe reuses the sentinel credentials unless dedicated
	// master ones are configured (an explicitly empty master password
	// disables AUTH on the probe; an empty username authenticates with the
	// password alone, i.e. requirepass or the "default" ACL user).
	masterUsername := username
	if cfg.MasterUsername != nil {
		masterUsername = *cfg.MasterUsername
	}
	masterPassword := password
	if cfg.MasterPassword != nil {
		masterPassword = *cfg.MasterPassword
	}

	return &RedisMasterResolver{
		masterName:               *cfg.Master,
		sentinel:                 redis.NewSentinelClient(clientOptions(*cfg.Sentinel, username, password, cfg.SentinelTLSConfig())),
		masterTLSConf:            cfg.MasterProbeTLSConfig(),
		masterUsername:           masterUsername,
		masterPassword:           masterPassword,
		retryOnMasterResolveFail: *cfg.ResolveRetries,
		trackReplicas:            *cfg.ReplicaListen != "",
		masterAddrLock:           &sync.RWMutex{},
		initialMasterResolveLock: make(chan struct{}),
	}
}

func (r *RedisMasterResolver) MasterAddress() string {
	<-r.initialMasterResolveLock

	r.masterAddrLock.RLock()
	defer r.masterAddrLock.RUnlock()
	return r.masterAddr
}

func (r *RedisMasterResolver) setMasterAddress(masterAddr *net.TCPAddr) {
	r.masterAddrLock.Lock()
	defer r.masterAddrLock.Unlock()
	r.masterAddr = masterAddr.String()
}

// ReplicaAddress returns the address of a healthy replica, rotating through
// the known set (round-robin per call). ok is false while no healthy replica
// is known; the caller decides whether to fall back to the master or reject.
// Like MasterAddress it blocks until the initial resolve has completed.
func (r *RedisMasterResolver) ReplicaAddress() (addr string, ok bool) {
	<-r.initialMasterResolveLock

	r.masterAddrLock.RLock()
	defer r.masterAddrLock.RUnlock()
	if len(r.replicaAddrs) == 0 {
		return "", false
	}
	idx := (r.replicaIdx.Add(1) - 1) % uint64(len(r.replicaAddrs))
	return r.replicaAddrs[idx], true
}

func (r *RedisMasterResolver) setReplicaAddresses(replicaAddrs []string) {
	r.masterAddrLock.Lock()
	defer r.masterAddrLock.Unlock()
	if !slices.Equal(r.replicaAddrs, replicaAddrs) {
		log.Printf("Healthy replicas: %v", replicaAddrs)
	}
	r.replicaAddrs = replicaAddrs
}

func (r *RedisMasterResolver) updateMasterAddress(ctx context.Context) error {
	masterAddr, err := r.resolveMasterAddress(ctx)
	if err != nil {
		log.Println(err)
		return err
	}
	r.setMasterAddress(masterAddr)

	// Replica tracking is best-effort: a failure must not invalidate the
	// successfully resolved master, so it doesn't count against the retry
	// budget. The replica endpoint handles an empty set via its fallback.
	if r.trackReplicas {
		replicaAddrs, err := r.resolveReplicaAddresses(ctx)
		if err != nil {
			log.Printf("error resolving replicas: %s", err)
			replicaAddrs = nil
		}
		r.setReplicaAddresses(replicaAddrs)
	}
	return nil
}

func (r *RedisMasterResolver) UpdateMasterAddressLoop(ctx context.Context) error {
	defer r.sentinel.Close()

	if err := r.initialMasterAddressResolve(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var err error
	for errCount := 0; errCount <= r.retryOnMasterResolveFail; {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		err = r.updateMasterAddress(ctx)
		switch {
		case err == nil:
			errCount = 0
		case errors.Is(err, errSentinelNotReady):
			// Sentinel is restarting; this fixes itself once it's
			// reconfigured with the real master, so wait it out instead of
			// counting it against the retry budget.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(sentinelNotReadyBackoff):
			}
		default:
			errCount++
		}
	}
	return err
}

// initialMasterAddressResolve resolves the master address for the first
// time, retrying up to retryOnMasterResolveFail times (with a 1-second
// backoff) before giving up. Without this, a single sentinel replica behind
// a multi-A-record DNS name (e.g. a Kubernetes headless service) that
// hasn't yet learned about the master would permanently fail startup.
func (r *RedisMasterResolver) initialMasterAddressResolve(ctx context.Context) error {
	defer close(r.initialMasterResolveLock)

	var err error
	for errCount := 0; ; {
		if err = r.updateMasterAddress(ctx); err == nil {
			return nil
		}

		wait := time.Second
		if errors.Is(err, errSentinelNotReady) {
			// Sentinel is up but still in its startup phase; this always
			// resolves itself once it's reconfigured with the real master,
			// so wait longer and don't count it against the retry budget.
			wait = sentinelNotReadyBackoff
		} else {
			errCount++
			if errCount > r.retryOnMasterResolveFail {
				break
			}
		}

		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
	return err
}

func (r *RedisMasterResolver) resolveMasterAddress(ctx context.Context) (*net.TCPAddr, error) {
	reply, err := r.sentinel.GetMasterAddrByName(ctx, r.masterName).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("sentinel returned nil reply (unknown master name?)")
		}
		return nil, fmt.Errorf("error getting master address from sentinel: %w", err)
	}
	if len(reply) != 2 {
		return nil, fmt.Errorf("expected 2 elements from sentinel, got %d", len(reply))
	}

	addr, err := usableTCPAddr(reply[0], reply[1])
	if err != nil {
		return nil, err
	}

	// Check that the address sentinel gave us is actually a writable master,
	// not e.g. a demoted former master that's still reachable but now a
	// replica (sentinel's view can be briefly stale during a failover).
	if err := r.checkRole(ctx, addr, "master"); err != nil {
		return nil, fmt.Errorf("error checking redis master: %w", err)
	}

	return addr, nil
}

// resolveReplicaAddresses asks sentinel for the replicas of the master group
// and returns the addresses of those that look usable: not flagged down or
// disconnected by sentinel, with a working replication link, and actually
// reporting role "slave" when probed (a replica mid-promotion reports
// "master" and is skipped - it will be picked up as the master instead).
// The result is sorted so callers can compare consecutive snapshots.
func (r *RedisMasterResolver) resolveReplicaAddresses(ctx context.Context) ([]string, error) {
	replicas, err := r.sentinel.Replicas(ctx, r.masterName).Result()
	if err != nil {
		return nil, fmt.Errorf("error getting replicas from sentinel: %w", err)
	}

	var addrs []string
	for _, fields := range replicas {
		if flags := fields["flags"]; strings.Contains(flags, "s_down") ||
			strings.Contains(flags, "o_down") || strings.Contains(flags, "disconnected") {
			continue
		}
		if link, ok := fields["master-link-status"]; ok && link != "ok" {
			continue
		}

		addr, err := usableTCPAddr(fields["ip"], fields["port"])
		if err != nil {
			continue
		}
		if err := r.checkRole(ctx, addr, "slave"); err != nil {
			continue
		}
		addrs = append(addrs, addr.String())
	}
	slices.Sort(addrs)
	return addrs, nil
}

// usableTCPAddr validates and resolves a host/port pair reported by
// sentinel. Sentinel briefly monitors a placeholder 0.0.0.0 (or ::) right
// after it restarts, before it's reconfigured with the real master address.
// Linux treats a connect to 0.0.0.0 as a connect to localhost, so accepting
// it here would make the role probe "succeed" against the proxy's own
// listener and send every client into a self-connect loop. Wrapping
// errSentinelNotReady makes the retry loops wait this phase out with a
// longer backoff instead of exhausting their retries before sentinel is
// ready. Sentinel can also be configured to announce a hostname (e.g. a
// Kubernetes headless-service DNS name) instead of an IP, which is not a
// placeholder and is fine to resolve normally.
func usableTCPAddr(host, port string) (*net.TCPAddr, error) {
	if host == "" || port == "" {
		return nil, fmt.Errorf("sentinel returned empty address %q:%q", host, port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return nil, fmt.Errorf("sentinel returned placeholder host %q: %w", host, errSentinelNotReady)
	}
	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("sentinel returned invalid port %q", port)
	}

	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("error resolving redis node: %w", err)
	}
	return addr, nil
}

// checkRole connects to addr and confirms it currently identifies as
// wantRole ("master" or "slave") via the ROLE command, rejecting addresses
// whose actual role no longer matches sentinel's view (which can be briefly
// stale during a failover). The probe uses the master TLS settings and
// password - they must match how the proxy itself dials the backend
// (MasterTLS), otherwise a TLS-enabled backend resets the plaintext probe.
func (r *RedisMasterResolver) checkRole(ctx context.Context, addr *net.TCPAddr, wantRole string) error {
	client := redis.NewClient(clientOptions(addr.String(), r.masterUsername, r.masterPassword, r.masterTLSConf))
	defer client.Close()

	reply, err := client.Do(ctx, "ROLE").Slice()
	if err != nil {
		return fmt.Errorf("error querying ROLE: %w", err)
	}
	if len(reply) == 0 {
		return fmt.Errorf("empty ROLE reply")
	}
	role, ok := reply[0].(string)
	if !ok {
		return fmt.Errorf("unexpected ROLE reply element of type %T", reply[0])
	}
	if role != wantRole {
		return fmt.Errorf("resolved address is not a %s (role=%q)", wantRole, role)
	}
	return nil
}
