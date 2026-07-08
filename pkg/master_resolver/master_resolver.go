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

// errSentinelNotReady marks resolve failures that fix themselves — sentinel's
// 0.0.0.0/:: startup placeholder, or an announced hostname whose DNS record
// is temporarily gone (restarting Kubernetes pod). The retry loops wait these
// out instead of counting them against the retry budget.
var errSentinelNotReady = errors.New("sentinel is not ready yet")

// Vars (not consts) so tests can shorten them.
var sentinelNotReadyBackoff = 10 * time.Second
var refreshThrottle = time.Second // min interval between RefreshAddresses resolves

// resolveFailureBackoffCap caps the progressive wait between failed resolves.
const resolveFailureBackoffCap = 30 * time.Second

// ResolveFailureBackoff returns 1s after the first failure, doubled per
// consecutive failure, capped.
func ResolveFailureBackoff(errCount int) time.Duration {
	if errCount < 1 {
		return time.Second
	}
	if errCount > 5 { // 1s << 5 is already past the cap
		return resolveFailureBackoffCap
	}
	return min(time.Second<<(errCount-1), resolveFailureBackoffCap)
}

type RedisMasterResolver struct {
	masterName               string
	sentinel                 *redis.SentinelClient
	masterTLSConf            *tls.Config
	masterUsername           string
	masterPassword           string
	retryOnMasterResolveFail int
	trackReplicas            bool
	debug                    bool

	masterAddrLock           *sync.RWMutex
	initialMasterResolveLock chan struct{}

	refreshLock sync.Mutex // serializes RefreshAddresses
	lastRefresh time.Time  // guarded by refreshLock

	masterAddr   string
	replicaAddrs []string
	replicaIdx   atomic.Uint64
}

// clientOptions builds the go-redis options shared by the sentinel client and
// the role probes: 1s per-operation timeouts, no client-side retries (the
// loops retry themselves), no CLIENT SETINFO chatter.
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

func NewRedisMasterResolver(cfg *config.Config) *RedisMasterResolver {
	var username string
	if cfg.Username != nil {
		username = *cfg.Username
	}
	var password string
	if cfg.Password != nil {
		password = *cfg.Password
	}

	// The role probe reuses the sentinel credentials unless dedicated master
	// ones are configured (explicitly empty password = probe without AUTH).
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
		trackReplicas:            cfg.ReplicaListen != nil && *cfg.ReplicaListen != "",
		debug:                    cfg.Debug != nil && *cfg.Debug,
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
	addr := masterAddr.String()
	r.masterAddrLock.Lock()
	defer r.masterAddrLock.Unlock()
	if r.debug && r.masterAddr != addr {
		if r.masterAddr == "" {
			log.Printf("[debug] master %s", addr)
		} else {
			log.Printf("[debug] master changed: %s -> %s", r.masterAddr, addr)
		}
	}
	r.masterAddr = addr
}

// ReplicaAddress returns a healthy replica (round-robin per call); ok is
// false while none is known. Blocks until the initial resolve has completed.
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
	if r.debug && !slices.Equal(r.replicaAddrs, replicaAddrs) {
		log.Printf("[debug] healthy replicas changed: %v -> %v", r.replicaAddrs, replicaAddrs)
	}
	r.replicaAddrs = replicaAddrs
}

// RefreshAddresses forces an immediate re-resolve of the master and replica
// addresses; the proxy calls it after failing to reach a backend. Calls are
// serialized and throttled, and failures never count against the update
// loop's retry budget.
func (r *RedisMasterResolver) RefreshAddresses(ctx context.Context) {
	select {
	case <-r.initialMasterResolveLock:
	default:
		return // initial resolve still running
	}

	r.refreshLock.Lock()
	defer r.refreshLock.Unlock()
	if time.Since(r.lastRefresh) < refreshThrottle {
		return
	}
	r.lastRefresh = time.Now()
	_ = r.updateMasterAddress(ctx) // it logs its own errors
}

func (r *RedisMasterResolver) updateMasterAddress(ctx context.Context) error {
	masterAddr, err := r.resolveMasterAddress(ctx)
	if err != nil {
		log.Println(err)
		return err
	}
	r.setMasterAddress(masterAddr)

	// Replica tracking is best-effort: a failure must not invalidate the
	// freshly resolved master.
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

		var wait time.Duration
		err = r.updateMasterAddress(ctx)
		switch {
		case err == nil:
			errCount = 0
			continue
		case errors.Is(err, errSentinelNotReady):
			// Fixes itself; wait it out without burning the retry budget.
			wait = sentinelNotReadyBackoff
		default:
			errCount++
			wait = ResolveFailureBackoff(errCount)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	return err
}

// initialMasterAddressResolve retries the first resolve up to
// retryOnMasterResolveFail times so a sentinel behind a multi-A-record DNS
// name that hasn't yet learned the master doesn't permanently fail startup.
func (r *RedisMasterResolver) initialMasterAddressResolve(ctx context.Context) error {
	defer close(r.initialMasterResolveLock)

	var err error
	for errCount := 0; ; {
		if err = r.updateMasterAddress(ctx); err == nil {
			return nil
		}

		var wait time.Duration
		if errors.Is(err, errSentinelNotReady) {
			// Fixes itself; wait it out without burning the retry budget.
			wait = sentinelNotReadyBackoff
		} else {
			errCount++
			if errCount > r.retryOnMasterResolveFail {
				break
			}
			wait = ResolveFailureBackoff(errCount)
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

	// Sentinel's view can be briefly stale during a failover; confirm the
	// node is actually a writable master.
	if err := r.checkRole(ctx, addr, "master"); err != nil {
		return nil, fmt.Errorf("error checking redis master: %w", err)
	}

	return addr, nil
}

// resolveReplicaAddresses returns the usable replicas of the master group:
// not flagged down or disconnected by sentinel, replication link up, and
// answering a ROLE probe with "slave". Sorted for snapshot comparison.
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
// sentinel. The 0.0.0.0/:: placeholder sentinel monitors right after a
// restart must be rejected (as errSentinelNotReady): Linux treats a connect
// to 0.0.0.0 as localhost, so the role probe would "succeed" against the
// proxy's own listener and send clients into a self-connect loop.
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
		// A hostname that doesn't resolve right now (restarting pod behind a
		// headless service) is the DNS flavor of the placeholder: waited out,
		// not counted against the retry budget.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, fmt.Errorf("error resolving redis node: %v: %w", err, errSentinelNotReady)
		}
		return nil, fmt.Errorf("error resolving redis node: %w", err)
	}
	return addr, nil
}

// checkRole confirms addr currently reports wantRole ("master" or "slave")
// via the ROLE command. The probe must use the master TLS/credential
// settings, otherwise a TLS-enabled backend resets the plaintext probe.
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
