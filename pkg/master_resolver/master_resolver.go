package masterresolver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/utils"
)

// maxRESPBulkLen bounds bulk-string sizes we accept from sentinel, so a
// misbehaving server can't make us allocate arbitrary amounts of memory.
const maxRESPBulkLen = 4096

// maxRESPArrayLen bounds array sizes we accept from sentinel (number of
// replicas and number of fields per replica), for the same reason.
const maxRESPArrayLen = 1024

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
	sentinelAddr             string
	sentinelTLSConf          *tls.Config
	masterTLSConf            *tls.Config
	sentinelPassword         string
	masterPassword           string
	retryOnMasterResolveFail int
	trackReplicas            bool

	masterAddrLock           *sync.RWMutex
	initialMasterResolveLock chan struct{}

	masterAddr   string
	replicaAddrs []string
	replicaIdx   atomic.Uint64
}

// NewRedisMasterResolver creates a resolver that queries sentinel at
// sentinelAddr. A non-nil sentinelTLSConf makes the sentinel connection use
// TLS; the connection to the resolved master is unaffected.
// func NewRedisMasterResolver(masterName string, sentinelAddr string, sentinelPassword string, retryOnMasterResolveFail int, sentinelTLSConf *tls.Config) *RedisMasterResolver {
func NewRedisMasterResolver(cfg *config.Config) *RedisMasterResolver {
	var password string
	if cfg.Password != nil {
		password = *cfg.Password
	}

	// The master-role probe reuses the sentinel password unless a dedicated
	// master password is configured (an explicitly empty one disables AUTH on
	// the probe).
	masterPassword := password
	if cfg.MasterPassword != nil {
		masterPassword = *cfg.MasterPassword
	}

	return &RedisMasterResolver{
		masterName:               *cfg.Master,
		sentinelAddr:             *cfg.Sentinel,
		sentinelTLSConf:          cfg.SentinelTLSConfig(),
		masterTLSConf:            cfg.MasterProbeTLSConfig(),
		sentinelPassword:         password,
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

func (r *RedisMasterResolver) updateMasterAddress() error {
	masterAddr, err := redisMasterFromSentinelAddr(r.sentinelAddr, r.sentinelTLSConf, r.masterTLSConf, r.sentinelPassword, r.masterPassword, r.masterName)
	if err != nil {
		log.Println(err)
		return err
	}
	r.setMasterAddress(masterAddr)

	// Replica tracking is best-effort: a failure must not invalidate the
	// successfully resolved master, so it doesn't count against the retry
	// budget. The replica endpoint handles an empty set via its fallback.
	if r.trackReplicas {
		replicaAddrs, err := redisReplicasFromSentinelAddr(r.sentinelAddr, r.sentinelTLSConf, r.masterTLSConf, r.sentinelPassword, r.masterPassword, r.masterName)
		if err != nil {
			log.Printf("error resolving replicas: %s", err)
			replicaAddrs = nil
		}
		r.setReplicaAddresses(replicaAddrs)
	}
	return nil
}

func (r *RedisMasterResolver) UpdateMasterAddressLoop(ctx context.Context) error {
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

		err = r.updateMasterAddress()
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
		if err = r.updateMasterAddress(); err == nil {
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

// dialSentinel opens an authenticated connection to sentinel with a 1-second
// deadline. The caller must close the returned connection.
func dialSentinel(sentinelAddress string, sentinelTLSConf *tls.Config, sentinelPassword string) (net.Conn, *bufio.Reader, error) {
	conn, err := dialRESP(sentinelAddress, sentinelTLSConf)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to sentinel: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("error setting deadline on sentinel connection: %w", err)
	}

	reader := bufio.NewReader(conn)

	if sentinelPassword != "" {
		if _, err := conn.Write(encodeRESPCommand("AUTH", sentinelPassword)); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("error sending AUTH to sentinel: %w", err)
		}
		if err := readRESPOK(reader); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("sentinel AUTH failed: %w", err)
		}
	}
	return conn, reader, nil
}

func redisMasterFromSentinelAddr(sentinelAddress string, sentinelTLSConf *tls.Config, masterTLSConf *tls.Config, sentinelPassword string, masterPassword string, masterName string) (*net.TCPAddr, error) {
	conn, reader, err := dialSentinel(sentinelAddress, sentinelTLSConf, sentinelPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Request master address
	if _, err := conn.Write(encodeRESPCommand("SENTINEL", "get-master-addr-by-name", masterName)); err != nil {
		return nil, fmt.Errorf("error writing to sentinel: %w", err)
	}

	reply, err := readRESPStringArray(reader, 2)
	if err != nil {
		return nil, fmt.Errorf("error getting master address from sentinel: %w", err)
	}

	host, port := reply[0], reply[1]

	// Sentinel briefly monitors a placeholder 0.0.0.0 (or ::) right after it
	// restarts, before it's reconfigured with the real master address. Linux
	// treats a connect to 0.0.0.0 as a connect to localhost, so accepting it
	// here would make checkMasterRole "succeed" against the proxy's own
	// listener and send every client into a self-connect loop. Wrapping
	// errSentinelNotReady makes the retry loops wait this phase out with a
	// longer backoff instead of exhausting their retries before sentinel is
	// ready. Sentinel can also be configured to announce a hostname (e.g. a
	// Kubernetes headless-service DNS name) instead of an IP, which is not a
	// placeholder and is fine to resolve normally below.
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return nil, fmt.Errorf("sentinel returned placeholder master host %q: %w", host, errSentinelNotReady)
	}

	if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
		return nil, fmt.Errorf("sentinel returned invalid master port %q", port)
	}

	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("error resolving redis master: %w", err)
	}

	// Check that the address sentinel gave us is actually a writable master,
	// not e.g. a demoted former master that's still reachable but now a
	// replica (sentinel's view can be briefly stale during a failover).
	if err := checkRole(addr, masterTLSConf, masterPassword, "master"); err != nil {
		return nil, fmt.Errorf("error checking redis master: %w", err)
	}

	return addr, nil
}

// redisReplicasFromSentinelAddr asks sentinel for the replicas of masterName
// and returns the addresses of those that look usable: not flagged down or
// disconnected by sentinel, with a working replication link, and actually
// reporting role "slave" when probed (a replica mid-promotion reports
// "master" and is skipped - it will be picked up as the master instead).
// The result is sorted so callers can compare consecutive snapshots.
func redisReplicasFromSentinelAddr(sentinelAddress string, sentinelTLSConf *tls.Config, masterTLSConf *tls.Config, sentinelPassword string, masterPassword string, masterName string) ([]string, error) {
	conn, reader, err := dialSentinel(sentinelAddress, sentinelTLSConf, sentinelPassword)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(encodeRESPCommand("SENTINEL", "replicas", masterName)); err != nil {
		return nil, fmt.Errorf("error writing to sentinel: %w", err)
	}

	replicas, err := readRESPFieldMaps(reader)
	if err != nil {
		return nil, fmt.Errorf("error getting replicas from sentinel: %w", err)
	}

	var addrs []string
	for _, fields := range replicas {
		host, port := fields["ip"], fields["port"]
		if host == "" || port == "" {
			continue
		}
		if flags := fields["flags"]; strings.Contains(flags, "s_down") ||
			strings.Contains(flags, "o_down") || strings.Contains(flags, "disconnected") {
			continue
		}
		if link, ok := fields["master-link-status"]; ok && link != "ok" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			continue
		}
		if portNum, err := strconv.Atoi(port); err != nil || portNum < 1 || portNum > 65535 {
			continue
		}

		addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
		if err != nil {
			continue
		}
		if err := checkRole(addr, masterTLSConf, masterPassword, "slave"); err != nil {
			continue
		}
		addrs = append(addrs, addr.String())
	}
	slices.Sort(addrs)
	return addrs, nil
}

// readRESPFieldMaps reads a RESP array of arrays of bulk strings, where each
// inner array is a flat field-name/value list (the shape of SENTINEL
// replicas/masters/sentinels replies), and returns one map per inner array.
func readRESPFieldMaps(r *bufio.Reader) ([]map[string]string, error) {
	n, err := readRESPArrayHeader(r)
	if err != nil {
		return nil, err
	}

	maps := make([]map[string]string, 0, n)
	for range n {
		m, err := readRESPArrayHeader(r)
		if err != nil {
			return nil, err
		}
		if m%2 != 0 {
			return nil, fmt.Errorf("expected an even number of field elements, got %d", m)
		}

		fields := make(map[string]string, m/2)
		for range m / 2 {
			key, err := readRESPBulkString(r)
			if err != nil {
				return nil, err
			}
			val, err := readRESPBulkString(r)
			if err != nil {
				return nil, err
			}
			fields[key] = val
		}
		maps = append(maps, fields)
	}
	return maps, nil
}

// readRESPArrayHeader reads a "*N" array header, rejecting error replies,
// nil arrays and sizes beyond maxRESPArrayLen.
func readRESPArrayHeader(r *bufio.Reader) (int, error) {
	header, err := readRESPLine(r)
	if err != nil {
		return 0, err
	}
	switch {
	case strings.HasPrefix(header, "-"):
		return 0, fmt.Errorf("sentinel error: %q", header[1:])
	case header == "*-1":
		return 0, fmt.Errorf("sentinel returned nil reply")
	case !strings.HasPrefix(header, "*"):
		return 0, fmt.Errorf("unexpected reply: %q", header)
	}

	n, err := strconv.Atoi(header[1:])
	if err != nil || n < 0 || n > maxRESPArrayLen {
		return 0, fmt.Errorf("invalid array size: %q", header)
	}
	return n, nil
}

// encodeRESPCommand encodes a command as a RESP array of bulk strings. Unlike
// the inline command format, bulk strings are binary-safe, so arguments
// containing spaces or CRLF cannot inject additional commands.
func encodeRESPCommand(args ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(arg), arg)
	}
	return b.Bytes()
}

// readRESPLine reads one CRLF-terminated RESP line. ReadSlice is bounded by
// the bufio buffer size, so an endless unterminated line cannot exhaust memory.
func readRESPLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

func readRESPOK(r *bufio.Reader) error {
	line, err := readRESPLine(r)
	if err != nil {
		return err
	}
	if line != "+OK" {
		return fmt.Errorf("unexpected reply: %q", line)
	}
	return nil
}

// readRESPStringArray reads a RESP array of exactly want bulk strings.
func readRESPStringArray(r *bufio.Reader, want int) ([]string, error) {
	header, err := readRESPLine(r)
	if err != nil {
		return nil, err
	}
	// %q on reply fragments: they are attacker-influenceable network bytes,
	// so quoting prevents control characters from forging log lines.
	switch {
	case strings.HasPrefix(header, "-"):
		return nil, fmt.Errorf("sentinel error: %q", header[1:])
	case header == "*-1" || header == "$-1":
		return nil, fmt.Errorf("sentinel returned nil reply (unknown master name?)")
	case !strings.HasPrefix(header, "*"):
		return nil, fmt.Errorf("unexpected reply: %q", header)
	}

	n, err := strconv.Atoi(header[1:])
	if err != nil || n != want {
		return nil, fmt.Errorf("expected array of %d elements, got: %q", want, header)
	}

	elems := make([]string, n)
	for i := range elems {
		elems[i], err = readRESPBulkString(r)
		if err != nil {
			return nil, err
		}
	}
	return elems, nil
}

func readRESPBulkString(r *bufio.Reader) (string, error) {
	sizeLine, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(sizeLine, "$") {
		return "", fmt.Errorf("expected bulk string, got: %q", sizeLine)
	}
	size, err := strconv.Atoi(sizeLine[1:])
	if err != nil || size < 0 || size > maxRESPBulkLen {
		return "", fmt.Errorf("invalid bulk string size: %q", sizeLine)
	}

	buf := make([]byte, size+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	if !bytes.HasSuffix(buf, []byte("\r\n")) {
		return "", fmt.Errorf("malformed bulk string")
	}
	return string(buf[:size]), nil
}

// dialRESP opens a connection to a RESP-speaking server (sentinel or the
// resolved master), using TLS when tlsConf is non-nil.
func dialRESP(addr string, tlsConf *tls.Config) (net.Conn, error) {
	if tlsConf != nil {
		return utils.TLSConnectWithTimeout(addr, tlsConf)
	}
	return utils.TCPConnectWithTimeout(addr)
}

// checkRole connects to addr and confirms it currently identifies as
// wantRole ("master" or "slave") via the ROLE command, rejecting addresses
// whose actual role no longer matches sentinel's view (which can be briefly
// stale during a failover). A non-nil tlsConf makes the probe use TLS - it
// must match how the proxy itself dials the backend (MasterTLS), otherwise a
// TLS-enabled backend resets the plaintext probe.
func checkRole(addr *net.TCPAddr, tlsConf *tls.Config, password string, wantRole string) error {
	conn, err := dialRESP(addr.String(), tlsConf)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("error setting deadline on master connection: %w", err)
	}
	reader := bufio.NewReader(conn)

	if password != "" {
		if _, err := conn.Write(encodeRESPCommand("AUTH", password)); err != nil {
			return fmt.Errorf("error sending AUTH to master: %w", err)
		}
		if err := readRESPOK(reader); err != nil {
			return fmt.Errorf("master AUTH failed: %w", err)
		}
	}

	if _, err := conn.Write(encodeRESPCommand("ROLE")); err != nil {
		return fmt.Errorf("error sending ROLE: %w", err)
	}
	role, err := readRESPRoleReply(reader)
	if err != nil {
		return fmt.Errorf("error reading ROLE reply: %w", err)
	}
	if role != wantRole {
		return fmt.Errorf("resolved address is not a %s (role=%q)", wantRole, role)
	}
	return nil
}

// readRESPRoleReply reads the reply to a ROLE command and returns just its
// first element (the role name). The remaining elements have a shape that
// varies by role (an integer offset followed by either a list of connected
// replicas for a master, or the perceived master's host/port/offset for a
// replica), so unlike readRESPStringArray this doesn't validate or consume
// the full array - the caller closes the connection right after anyway.
func readRESPRoleReply(r *bufio.Reader) (string, error) {
	header, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasPrefix(header, "-"):
		return "", fmt.Errorf("master error: %q", header[1:])
	case !strings.HasPrefix(header, "*"):
		return "", fmt.Errorf("unexpected reply: %q", header)
	}

	n, err := strconv.Atoi(header[1:])
	if err != nil || n < 1 {
		return "", fmt.Errorf("expected non-empty ROLE array, got: %q", header)
	}

	return readRESPBulkString(r)
}
