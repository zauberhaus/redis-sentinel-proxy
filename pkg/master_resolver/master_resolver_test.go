// cspell:words NOTOK RESPOK sekret notabulk
package masterresolver_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	masterresolver "github.com/zauberhaus/redis-sentinel-proxy/pkg/master_resolver"
)

const (
	testMasterName    = "test-master"
	testPassword      = "sekret pass\r\nwith tricky chars"
	testMasterPass    = "different master pass"
	testUsername      = "acl-user"
	mockServerPort    = 12700
	unusedServerPort  = 12701
	mockTLSServerPort = 12702
	demotedMasterPort = 12703
	tlsMasterPort     = 12704
	secondReplicaPort = 12705
)

// respBulkString encodes a single RESP bulk string, e.g. for the first
// element of a ROLE reply.
func respBulkString(s string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(s), s)
}

// roleReply builds a minimal-but-well-formed RESP reply to a ROLE command
// reporting the given role ("master" or "slave").
func roleReply(role string) string {
	if role == "master" {
		// role, replication offset, empty replica list
		return "*3\r\n" + respBulkString("master") + ":0\r\n*0\r\n"
	}
	// role, master host, master port, link status, replication offset
	return "*5\r\n" + respBulkString("slave") + respBulkString("127.0.0.1") + ":0\r\n" + respBulkString("connect") + ":0\r\n"
}

func ptr[T any](v T) *T { return &v }

// newResolver builds a resolver via the config-based constructor for tests
// that only need plain TCP and a fixed retry count.
func newResolver(t *testing.T, addr, master string, retries int) *masterresolver.RedisMasterResolver {
	t.Helper()

	cfg, err := config.Load(&config.Config{
		Sentinel:       ptr(addr),
		Master:         ptr(master),
		Password:       ptr(""),
		ResolveRetries: ptr(retries),
	}, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return masterresolver.NewRedisMasterResolver(cfg)
}

func TestResolveMasterAddress(t *testing.T) {
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}

	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	serverCert, caFile := generateSelfSignedCert(t)
	tlsListener, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", mockTLSServerPort), &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("could not start mock TLS sentinel: %v", err)
	}
	defer tlsListener.Close()
	go mockSentinelServer(tlsListener)

	tlsServerAddr := fmt.Sprintf("127.0.0.1:%d", mockTLSServerPort)

	// The expected resolved address for the "hostname-master" case is
	// computed the same way the resolver itself resolves it, so the
	// assertion doesn't hardcode a specific address family for "localhost".
	wantHostnameAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", mockServerPort))
	if err != nil {
		t.Fatalf("could not resolve localhost: %v", err)
	}
	wantHostnameMasterAddr := wantHostnameAddr.String()

	// tls-master backend: a TLS-only "master" (answers ROLE with "master"),
	// simulating a Redis with TLS enabled - the role probe must dial it with
	// the MasterTLS config, or the server resets the plaintext connection.
	tlsMasterListener, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tlsMasterPort), &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("could not start mock TLS master: %v", err)
	}
	defer tlsMasterListener.Close()
	go mockSentinelServer(tlsMasterListener)

	// demoted-master backend: reachable over plain TCP, but reports itself as
	// a replica via ROLE, simulating sentinel's view of the master being
	// stale (e.g. mid-failover, or an old master that's since been demoted).
	demotedMasterAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: demotedMasterPort}
	demotedListener, err := net.ListenTCP("tcp", demotedMasterAddr)
	if err != nil {
		t.Fatalf("could not start demoted-master backend: %v", err)
	}
	defer demotedListener.Close()
	go serveDemotedMasterConn(demotedListener)

	// want is left empty ("") for every case that should fail: the resolver
	// only ever assigns a non-empty master address after a fully successful
	// resolve, so an empty result is an equally valid signal of failure as a
	// returned error would be, without needing access to the unexported
	// resolve function directly.
	// tlsMode selects the client-side sentinel TLS setup: "" (plain TCP),
	// "valid" (TLS verified against caFile) or "untrusted" (TLS verified
	// against system roots only, so our self-signed cert is rejected).
	// masterTLS does the same for the connection probing the resolved master.
	tests := []struct {
		name      string
		addr      string
		tlsMode   string
		masterTLS string
		username  string
		password  string
		// masterUsername/masterPassword mirror the config fields: nil falls
		// back to the sentinel credential, an explicitly empty master
		// password disables AUTH on the role probe.
		masterUsername *string
		masterPassword *string
		master         string
		want           string
	}{
		{
			name:   "all is ok without auth",
			addr:   mockServerAddr.String(),
			master: testMasterName,
			want:   mockServerAddr.String(),
		},
		{
			name:     "all is ok with auth",
			addr:     mockServerAddr.String(),
			password: testPassword,
			master:   testMasterName,
			want:     mockServerAddr.String(),
		},
		{
			name:     "wrong password",
			addr:     mockServerAddr.String(),
			password: "wrong",
			master:   testMasterName,
		},
		{
			name:     "ACL username and password",
			addr:     mockServerAddr.String(),
			username: testUsername,
			password: testPassword,
			master:   testMasterName,
			want:     mockServerAddr.String(),
		},
		{
			name:     "wrong ACL username",
			addr:     mockServerAddr.String(),
			username: "wrong-user",
			password: testPassword,
			master:   testMasterName,
		},
		{
			// Sentinel is open, but the master requires an ACL user: only
			// the role probe must send the dedicated credentials.
			name:           "ACL credentials for the master only",
			addr:           mockServerAddr.String(),
			masterUsername: ptr(testUsername),
			masterPassword: ptr(testMasterPass),
			master:         testMasterName,
			want:           mockServerAddr.String(),
		},
		{
			name:           "master password differs from sentinel password",
			addr:           mockServerAddr.String(),
			password:       testPassword,
			masterPassword: ptr(testMasterPass),
			master:         testMasterName,
			want:           mockServerAddr.String(),
		},
		{
			// The sentinel AUTH succeeds; only the role probe's AUTH is
			// rejected, so a failure here proves the probe uses the dedicated
			// master password rather than the sentinel one.
			name:           "wrong master password",
			addr:           mockServerAddr.String(),
			password:       testPassword,
			masterPassword: ptr("wrong"),
			master:         testMasterName,
		},
		{
			// An explicitly empty master password disables AUTH on the role
			// probe (the mock rejects AUTH with an empty password, so success
			// proves no AUTH was sent).
			name:           "sentinel password with password-less master",
			addr:           mockServerAddr.String(),
			password:       testPassword,
			masterPassword: ptr(""),
			master:         testMasterName,
			want:           mockServerAddr.String(),
		},
		{
			name:     "connection closed during auth",
			addr:     mockServerAddr.String(),
			password: "trigger-close",
			master:   testMasterName,
		},
		{
			name:   "unknown master",
			addr:   mockServerAddr.String(),
			master: "bad-master",
		},
		{
			name:   "master without listener",
			addr:   mockServerAddr.String(),
			master: "unreachable-master",
		},
		{
			name:   "master reported by sentinel is actually a replica",
			addr:   mockServerAddr.String(),
			master: "demoted-master",
		},
		{
			name:      "master requires TLS",
			addr:      mockServerAddr.String(),
			masterTLS: "valid",
			master:    "tls-master",
			want:      fmt.Sprintf("127.0.0.1:%d", tlsMasterPort),
		},
		{
			// Without MasterTLS configured the role probe speaks plaintext
			// RESP to a TLS-only master, which resets the connection.
			name:   "plaintext probe against TLS-only master",
			addr:   mockServerAddr.String(),
			master: "tls-master",
		},
		{
			name:   "invalid master port",
			addr:   mockServerAddr.String(),
			master: "invalid-port-master",
		},
		{
			name:   "sentinel error reply",
			addr:   mockServerAddr.String(),
			master: "error-reply-master",
		},
		{
			name:   "nil bulk reply",
			addr:   mockServerAddr.String(),
			master: "nil-bulk-master",
		},
		{
			name:   "unexpected reply type",
			addr:   mockServerAddr.String(),
			master: "weird-reply-master",
		},
		{
			name:   "wrong element count",
			addr:   mockServerAddr.String(),
			master: "short-array-master",
		},
		{
			name:   "non-numeric element count",
			addr:   mockServerAddr.String(),
			master: "bad-count-master",
		},
		{
			name:   "element is not a bulk string",
			addr:   mockServerAddr.String(),
			master: "bad-element-type-master",
		},
		{
			name:   "non-numeric bulk size",
			addr:   mockServerAddr.String(),
			master: "bad-bulk-size-master",
		},
		{
			name:   "negative bulk size",
			addr:   mockServerAddr.String(),
			master: "negative-size-master",
		},
		{
			name:   "bulk size too large",
			addr:   mockServerAddr.String(),
			master: "huge-size-master",
		},
		{
			name:   "malformed bulk suffix",
			addr:   mockServerAddr.String(),
			master: "malformed-suffix-master",
		},
		{
			name:   "truncated bulk payload",
			addr:   mockServerAddr.String(),
			master: "truncated-payload-master",
		},
		{
			name:   "truncated element",
			addr:   mockServerAddr.String(),
			master: "truncated-master",
		},
		{
			name:   "connection closed while reading reply",
			addr:   mockServerAddr.String(),
			master: "closed-immediately-master",
		},
		{
			name:    "all is ok over TLS",
			addr:    tlsServerAddr,
			tlsMode: "valid",
			master:  testMasterName,
			want:    mockServerAddr.String(),
		},
		{
			name:     "TLS with auth",
			addr:     tlsServerAddr,
			tlsMode:  "valid",
			password: testPassword,
			master:   testMasterName,
			want:     mockServerAddr.String(),
		},
		{
			name:    "TLS with untrusted certificate",
			addr:    tlsServerAddr,
			tlsMode: "untrusted",
			master:  testMasterName,
		},
		{
			name:    "TLS against plaintext sentinel",
			addr:    mockServerAddr.String(),
			tlsMode: "valid",
			master:  testMasterName,
		},
		{
			// Sentinel can be configured to announce a DNS name (e.g. a
			// Kubernetes headless-service hostname) instead of an IP; this
			// must resolve like any other TCP address rather than being
			// rejected as unusable.
			name:   "master reported by hostname",
			addr:   mockServerAddr.String(),
			master: "hostname-master",
			want:   wantHostnameMasterAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveMaster(t, tt.addr, tt.tlsMode, tt.masterTLS, caFile,
				tt.username, tt.password, tt.masterUsername, tt.masterPassword, tt.master)
			if got != tt.want {
				t.Errorf("resolved master = %q, want %q", got, tt.want)
			}
		})
	}
}

// resolveMaster starts UpdateMasterAddressLoop in the background and returns
// what MasterAddress() unblocks with after the initial resolve.
func resolveMaster(t *testing.T, addr, tlsMode, masterTLSMode, caFile, username, password string, masterUsername, masterPassword *string, master string) string {
	t.Helper()

	sentinelTLS := &config.BackendTLS{Enabled: ptr(false)}
	switch tlsMode {
	case "valid":
		sentinelTLS = &config.BackendTLS{Enabled: ptr(true), CAFile: ptr(caFile)}
	case "untrusted":
		sentinelTLS = &config.BackendTLS{Enabled: ptr(true)}
	}

	masterTLS := &config.BackendTLS{Enabled: ptr(false)}
	if masterTLSMode == "valid" {
		masterTLS = &config.BackendTLS{Enabled: ptr(true), CAFile: ptr(caFile)}
	}

	cfg, err := config.Load(&config.Config{
		Sentinel:       ptr(addr),
		Master:         ptr(master),
		Username:       ptr(username),
		Password:       ptr(password),
		MasterUsername: masterUsername,
		MasterPassword: masterPassword,
		ResolveRetries: ptr(0),
		SentinelTLS:    sentinelTLS,
		MasterTLS:      masterTLS,
	}, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	r := masterresolver.NewRedisMasterResolver(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.UpdateMasterAddressLoop(ctx)

	done := make(chan string, 1)
	go func() { done <- r.MasterAddress() }()

	select {
	case got := <-done:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("MasterAddress() did not return in time")
		return ""
	}
}

// TestResolveReplicas: keep the healthy replicas, skip the down / broken-link
// / wrong-role ones, and rotate through the healthy set per call.
func TestResolveReplicas(t *testing.T) {
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}
	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	// Two healthy replicas answering ROLE with "slave".
	var replicaAddrs []string
	for _, port := range []int{demotedMasterPort, secondReplicaPort} {
		addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			t.Fatalf("could not start mock replica: %v", err)
		}
		defer l.Close()
		go serveDemotedMasterConn(l)
		replicaAddrs = append(replicaAddrs, addr.String())
	}

	cfg, err := config.Load(&config.Config{
		Sentinel:       ptr(mockServerAddr.String()),
		Master:         ptr(testMasterName),
		Password:       ptr(""),
		ResolveRetries: ptr(0),
		ReplicaListen:  ptr(":0"), // non-empty enables replica tracking
	}, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	r := masterresolver.NewRedisMasterResolver(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.UpdateMasterAddressLoop(ctx)

	done := make(chan string, 1)
	go func() { done <- r.MasterAddress() }()
	select {
	case got := <-done:
		if got != mockServerAddr.String() {
			t.Fatalf("MasterAddress() = %q, want %q", got, mockServerAddr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MasterAddress() did not return in time")
	}

	// Consecutive picks must rotate through both healthy replicas and
	// nothing else.
	first, ok := r.ReplicaAddress()
	if !ok {
		t.Fatal("ReplicaAddress() reported no healthy replica")
	}
	second, ok := r.ReplicaAddress()
	if !ok {
		t.Fatal("ReplicaAddress() reported no healthy replica on second call")
	}
	got := []string{first, second}
	slices.Sort(got)
	if !slices.Equal(got, replicaAddrs) {
		t.Errorf("ReplicaAddress() rotation = %v, want %v", got, replicaAddrs)
	}
}

// TestReplicaAddressWithoutTracking covers the disabled path: without a
// replica listener the resolver never queries sentinel for replicas and
// ReplicaAddress reports no replica.
func TestReplicaAddressWithoutTracking(t *testing.T) {
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}
	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	r := newResolver(t, mockServerAddr.String(), testMasterName, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.UpdateMasterAddressLoop(ctx)
	r.MasterAddress()

	if addr, ok := r.ReplicaAddress(); ok {
		t.Errorf("ReplicaAddress() = %q, want none with tracking disabled", addr)
	}
}

func TestRedisMasterResolverLifecycle(t *testing.T) {
	// The mock sentinel always redirects to mockServerPort as the "master",
	// so it must listen on that exact port for checkTCPConnect to succeed.
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}

	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	r := newResolver(t, mockServerAddr.String(), testMasterName, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.UpdateMasterAddressLoop(ctx)

	// MasterAddress() blocks until the initial resolve completes.
	done := make(chan string, 1)
	go func() { done <- r.MasterAddress() }()

	select {
	case got := <-done:
		if got != mockServerAddr.String() {
			t.Errorf("MasterAddress() = %q, want %q", got, mockServerAddr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MasterAddress() did not return in time")
	}

	// Calling it again should return immediately with the cached value,
	// without blocking on the initial resolve a second time.
	if got := r.MasterAddress(); got != mockServerAddr.String() {
		t.Errorf("second MasterAddress() = %q, want %q", got, mockServerAddr.String())
	}
}

func TestUpdateMasterAddressLoopInitialFailure(t *testing.T) {
	// Nothing listens on this port, so every resolve attempt fails; the loop
	// should retry retryOnMasterResolveFail times (with backoff) and then
	// return the error rather than retrying forever.
	r := newResolver(t, "127.0.0.1:1", testMasterName, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error from UpdateMasterAddressLoop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMasterAddressLoop did not return in time")
	}
}

func TestUpdateMasterAddressLoopInitialRetrySucceeds(t *testing.T) {
	// Nothing listens yet, so the first resolve attempt fails; start a mock
	// sentinel only after that, so the retry (not the initial attempt) is
	// what succeeds. The mock sentinel always redirects to mockServerPort as
	// the "master", so it must listen on that exact port.
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}

	r := newResolver(t, mockServerAddr.String(), testMasterName, 2)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	time.Sleep(200 * time.Millisecond)
	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	addrDone := make(chan string, 1)
	go func() { addrDone <- r.MasterAddress() }()

	select {
	case got := <-addrDone:
		if got != mockServerAddr.String() {
			t.Errorf("MasterAddress() = %q, want %q", got, mockServerAddr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MasterAddress() did not return in time")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("UpdateMasterAddressLoop() error = %v, want nil after context cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMasterAddressLoop did not return in time after cancel")
	}
}

func TestUpdateMasterAddressLoopTicks(t *testing.T) {
	// The mock sentinel always redirects to mockServerPort as the "master",
	// so it must listen on that exact port for checkTCPConnect to succeed.
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}

	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	r := newResolver(t, mockServerAddr.String(), testMasterName, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	// Let the 1-second ticker fire at least once with a successful resolve
	// (exercising the errCount-reset branch) before tearing down.
	time.Sleep(1200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("UpdateMasterAddressLoop() error = %v, want nil after context cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMasterAddressLoop did not return in time after cancel")
	}
}

func TestUpdateMasterAddressLoopStopsOnContextCancel(t *testing.T) {
	// The mock sentinel always redirects to mockServerPort as the "master",
	// so it must listen on that exact port for checkTCPConnect to succeed.
	mockServerAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: mockServerPort}

	listener, err := net.ListenTCP("tcp", mockServerAddr)
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer listener.Close()
	go mockSentinelServer(listener)

	r := newResolver(t, mockServerAddr.String(), testMasterName, 0)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	// Let the initial resolve happen, then cancel; the ticker-driven loop
	// should observe ctx.Done() and return nil rather than blocking forever.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("UpdateMasterAddressLoop() error = %v, want nil after context cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateMasterAddressLoop did not return in time after cancel")
	}
}

// TestResolverReflectsMasterChange: a failover reported by sentinel must be
// picked up by the ticker-driven loop without a restart.
func TestResolverReflectsMasterChange(t *testing.T) {
	backendA := startAcceptingListener(t)
	backendB := startAcceptingListener(t)
	addrA := backendA.Addr().(*net.TCPAddr)
	addrB := backendB.Addr().(*net.TCPAddr)

	var currentPort atomic.Int32
	currentPort.Store(int32(addrA.Port))

	sentinelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer sentinelListener.Close()
	go serveSwitchableSentinel(sentinelListener, &currentPort)

	r := newResolver(t, sentinelListener.Addr().String(), testMasterName, 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.UpdateMasterAddressLoop(ctx)

	wantA := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addrA.Port}).String()
	wantB := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addrB.Port}).String()

	if got := r.MasterAddress(); got != wantA {
		t.Fatalf("MasterAddress() = %q, want %q", got, wantA)
	}

	// Simulate a sentinel failover: it now reports backend B as the master.
	currentPort.Store(int32(addrB.Port))

	// The background loop only re-resolves once per second, so poll instead
	// of sleeping a fixed (and either racy or slow) amount.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := r.MasterAddress(); got == wantB {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("MasterAddress() = %q, want %q after the sentinel failover", r.MasterAddress(), wantB)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestResolveFailureBackoff(t *testing.T) {
	for _, tc := range []struct {
		errCount int
		want     time.Duration
	}{
		{0, time.Second},
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{5, 16 * time.Second},
		{6, 30 * time.Second},
		{100, 30 * time.Second},
	} {
		if got := masterresolver.ResolveFailureBackoff(tc.errCount); got != tc.want {
			t.Errorf("ResolveFailureBackoff(%d) = %v, want %v", tc.errCount, got, tc.want)
		}
	}
}

// TestUpdateMasterAddressLoopFailsAfterRetries verifies that persistent
// resolve failures after a successful start still terminate the loop once
// the retry budget is spent (with a progressive backoff between attempts).
func TestUpdateMasterAddressLoopFailsAfterRetries(t *testing.T) {
	backend := startAcceptingListener(t)

	var currentPort atomic.Int32
	currentPort.Store(int32(backend.Addr().(*net.TCPAddr).Port))

	sentinelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer sentinelListener.Close()
	go serveSwitchableSentinel(sentinelListener, &currentPort)

	r := newResolver(t, sentinelListener.Addr().String(), testMasterName, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	// Wait for the initial resolve, then break the resolve permanently:
	// sentinel now reports a master whose ROLE probe fails.
	r.MasterAddress()
	currentPort.Store(int32(unusedServerPort)) // nothing listens here

	// retries=1: first failure waits 1s, the second exceeds the budget, so
	// the loop must return the error (well within the 10s guard).
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("UpdateMasterAddressLoop returned nil, want the resolve error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UpdateMasterAddressLoop did not return after the retry budget was spent")
	}
}

// TestUpdateMasterAddressLoopSurvivesShortOutage: an outage shorter than the
// retry budget keeps the loop alive, serving the last known master meanwhile.
func TestUpdateMasterAddressLoopSurvivesShortOutage(t *testing.T) {
	backendA := startAcceptingListener(t)
	backendB := startAcceptingListener(t)
	portA := backendA.Addr().(*net.TCPAddr).Port
	portB := backendB.Addr().(*net.TCPAddr).Port
	deadPort := int32(unusedServerPort) // nothing listens here

	var currentPort atomic.Int32
	currentPort.Store(int32(portA))

	sentinelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer sentinelListener.Close()
	go serveSwitchableSentinel(sentinelListener, &currentPort)

	// retries=3 tolerates an outage of at least 1s+2s+4s of backoff waits.
	r := newResolver(t, sentinelListener.Addr().String(), testMasterName, 3)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.UpdateMasterAddressLoop(ctx) }()

	wantA := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA}).String()
	wantB := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portB}).String()
	if got := r.MasterAddress(); got != wantA {
		t.Fatalf("MasterAddress() = %q, want %q", got, wantA)
	}

	// Break the resolve: sentinel now reports a master whose ROLE probe
	// fails. A couple of resolves fail during this window, but fewer than
	// the retry budget allows.
	currentPort.Store(deadPort)
	select {
	case err := <-done:
		t.Fatalf("UpdateMasterAddressLoop returned (%v) instead of surviving resolve failures", err)
	case <-time.After(2500 * time.Millisecond):
	}

	// The last known master is still served while resolves fail.
	if got := r.MasterAddress(); got != wantA {
		t.Errorf("MasterAddress() during outage = %q, want last known %q", got, wantA)
	}

	// Sentinel recovers, now reporting a different master; the loop must
	// still be alive and pick it up.
	currentPort.Store(int32(portB))
	deadline := time.Now().Add(5 * time.Second)
	for r.MasterAddress() != wantB {
		if time.Now().After(deadline) {
			t.Fatalf("MasterAddress() = %q, want %q after recovery", r.MasterAddress(), wantB)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestRefreshAddresses: a refresh picks up a failover synchronously; a second
// refresh within the throttle window is a no-op.
func TestRefreshAddresses(t *testing.T) {
	backendA := startAcceptingListener(t)
	backendB := startAcceptingListener(t)
	addrA := backendA.Addr().(*net.TCPAddr)
	addrB := backendB.Addr().(*net.TCPAddr)

	var currentPort atomic.Int32
	currentPort.Store(int32(addrA.Port))

	sentinelListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start mock sentinel: %v", err)
	}
	defer sentinelListener.Close()
	go serveSwitchableSentinel(sentinelListener, &currentPort)

	r := newResolver(t, sentinelListener.Addr().String(), testMasterName, 0)
	ctx := context.Background()

	// Before the initial resolve has completed there is nothing to refresh;
	// the call must return immediately instead of blocking.
	r.RefreshAddresses(ctx)

	if err := r.InitialResolve(ctx); err != nil {
		t.Fatalf("InitialResolve() error = %v", err)
	}

	wantA := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addrA.Port}).String()
	wantB := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: addrB.Port}).String()

	if got := r.MasterAddress(); got != wantA {
		t.Fatalf("MasterAddress() = %q, want %q", got, wantA)
	}

	// Simulate a sentinel failover: it now reports backend B as the master.
	// The refresh must pick it up synchronously.
	currentPort.Store(int32(addrB.Port))
	r.RefreshAddresses(ctx)
	if got := r.MasterAddress(); got != wantB {
		t.Fatalf("MasterAddress() after refresh = %q, want %q", got, wantB)
	}

	// A second refresh right away falls into the throttle window and must
	// not resolve again, even though sentinel's answer has changed back.
	currentPort.Store(int32(addrA.Port))
	r.RefreshAddresses(ctx)
	if got := r.MasterAddress(); got != wantB {
		t.Fatalf("MasterAddress() after throttled refresh = %q, want %q (unchanged)", got, wantB)
	}
}

// TestResolverWaitsForSentinelStartup: the startup placeholder must be waited
// out instead of burning the retry budget (ResolveRetries is 0 here, so one
// ordinary failure would already give up).
func TestResolverWaitsForSentinelStartup(t *testing.T) {
	restore := masterresolver.SetSentinelNotReadyBackoff(20 * time.Millisecond)
	defer restore()

	// The third "placeholder" is the DNS flavor of the startup phase: sentinel
	// announces a hostname that doesn't currently resolve (e.g. a Kubernetes
	// pod behind a headless service that lost its DNS record while
	// restarting). It must be waited out the same way instead of counting
	// against the retry budget.
	for _, placeholder := range []string{"0.0.0.0", "::", "redis-0.does-not-exist.invalid"} {
		t.Run(placeholder, func(t *testing.T) {
			backend := startAcceptingListener(t)
			backendPort := backend.Addr().(*net.TCPAddr).Port

			var ready atomic.Bool
			sentinelListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("could not start mock sentinel: %v", err)
			}
			defer sentinelListener.Close()
			go serveStartupSentinel(sentinelListener, placeholder, backendPort, &ready)

			r := newResolver(t, sentinelListener.Addr().String(), testMasterName, 0)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go r.UpdateMasterAddressLoop(ctx)

			// Let the resolver hit the placeholder a few times before the
			// sentinel "finishes starting up".
			time.Sleep(100 * time.Millisecond)
			ready.Store(true)

			want := (&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: backendPort}).String()
			done := make(chan string, 1)
			go func() { done <- r.MasterAddress() }()

			select {
			case got := <-done:
				if got != want {
					t.Errorf("MasterAddress() = %q, want %q", got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("MasterAddress() did not return in time; resolver gave up or is stuck in the startup phase")
			}
		})
	}
}

// isCommand reports whether cmd is the given command with the given number
// of arguments. Redis command names are case-insensitive (go-redis sends
// them in lowercase).
func isCommand(cmd []string, name string, args int) bool {
	return len(cmd) == args+1 && strings.EqualFold(cmd[0], name)
}

// replyUnknownCommand answers an unrecognized command (e.g. HELLO) with an
// error reply so the client falls back to RESP2; reports whether the
// connection is still usable.
func replyUnknownCommand(c net.Conn, cmd []string) bool {
	_, err := fmt.Fprintf(c, "-ERR unknown command %q\r\n", cmd[0])
	return err == nil
}

// serveStartupSentinel answers get-master-addr-by-name with a placeholder
// host until ready flips to true, then with the real backend address,
// simulating a sentinel that's still in its startup phase.
func serveStartupSentinel(listener net.Listener, placeholderHost string, realPort int, ready *atomic.Bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			reader := bufio.NewReader(c)
			for {
				cmd, err := mockReadCommand(reader)
				if err != nil {
					return
				}
				if isCommand(cmd, "SENTINEL", 2) && cmd[1] == "get-master-addr-by-name" {
					host := placeholderHost
					if ready.Load() {
						host = "127.0.0.1"
					}
					if _, err := c.Write([]byte(respAddress(host, realPort))); err != nil {
						return
					}
					continue
				}
				if !replyUnknownCommand(c, cmd) {
					return
				}
			}
		}(conn)
	}
}

// startAcceptingListener starts a listener that just accepts and closes
// connections, enough to satisfy the resolver's checkTCPConnect probe
// against a stand-in "master".
func startAcceptingListener(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not start listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					cmd, err := mockReadCommand(reader)
					if err != nil {
						return
					}
					if isCommand(cmd, "ROLE", 0) {
						if _, err := c.Write([]byte(roleReply("master"))); err != nil {
							return
						}
						continue
					}
					if !replyUnknownCommand(c, cmd) {
						return
					}
				}
			}(conn)
		}
	}()
	return listener
}

// serveSwitchableSentinel answers every get-master-addr-by-name request with
// whatever port is currently stored in port, so a test can simulate a
// sentinel failover by changing it mid-test.
func serveSwitchableSentinel(listener net.Listener, port *atomic.Int32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			reader := bufio.NewReader(c)
			for {
				cmd, err := mockReadCommand(reader)
				if err != nil {
					return
				}
				if isCommand(cmd, "SENTINEL", 2) && cmd[1] == "get-master-addr-by-name" {
					reply := respAddress("127.0.0.1", int(port.Load()))
					if _, err := c.Write([]byte(reply)); err != nil {
						return
					}
					continue
				}
				if !replyUnknownCommand(c, cmd) {
					return
				}
			}
		}(conn)
	}
}

// generateSelfSignedCert creates a self-signed certificate for the mock TLS
// sentinel and returns it alongside a PEM CA file (on disk, since
// config.BackendTLS.CAFile is a file path) that trusts it.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-sentinel"},
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

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("could not parse certificate: %v", err)
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatalf("could not write CA file: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, caFile
}

// serveDemotedMasterConn answers ROLE with "slave" regardless of what's
// asked, simulating a reachable Redis instance that sentinel still believes
// is the master but which has actually been demoted to a replica.
func serveDemotedMasterConn(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			reader := bufio.NewReader(c)
			for {
				cmd, err := mockReadCommand(reader)
				if err != nil {
					return
				}
				if len(cmd) == 1 && strings.EqualFold(cmd[0], "ROLE") {
					if _, err := c.Write([]byte(roleReply("slave"))); err != nil {
						return
					}
					continue
				}
				// Unknown commands (e.g. the client library's HELLO
				// handshake) get an error reply so the client falls back
				// to RESP2 and proceeds with ROLE.
				if _, err := fmt.Fprintf(c, "-ERR unknown command %q\r\n", cmd[0]); err != nil {
					return
				}
			}
		}(conn)
	}
}

func mockSentinelServer(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go serveMockSentinelConn(conn)
	}
}

func serveMockSentinelConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	for {
		cmd, err := mockReadCommand(reader)
		if err != nil {
			return
		}

		reply, closeAfter := buildMockReply(cmd)
		if reply != "" {
			if _, err := conn.Write([]byte(reply)); err != nil {
				log.Println("could not write reply from mock sentinel:", err)
				return
			}
		}
		if closeAfter {
			return
		}
	}
}

// mockReadLine and mockReadBulkString: the mock server's own minimal RESP
// reader, deliberately independent of the production parsing helpers.
func mockReadLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func mockReadBulkString(r *bufio.Reader) (string, error) {
	sizeLine, err := mockReadLine(r)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(sizeLine, "$") {
		return "", fmt.Errorf("expected bulk string, got: %s", sizeLine)
	}
	size, err := strconv.Atoi(sizeLine[1:])
	if err != nil || size < 0 {
		return "", fmt.Errorf("invalid bulk string size: %s", sizeLine)
	}

	buf := make([]byte, size+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf[:size]), nil
}

// mockReadCommand reads one RESP command (array of bulk strings) of any arity.
func mockReadCommand(r *bufio.Reader) ([]string, error) {
	header, err := mockReadLine(r)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(header, "*") {
		return nil, fmt.Errorf("expected array, got: %s", header)
	}
	n, err := strconv.Atoi(header[1:])
	if err != nil || n < 1 {
		return nil, fmt.Errorf("invalid array header: %s", header)
	}

	cmd := make([]string, n)
	for i := range cmd {
		cmd[i], err = mockReadBulkString(r)
		if err != nil {
			return nil, err
		}
	}
	return cmd, nil
}

// buildMockReply maps a command to a raw RESP reply, selecting malformed
// variants by well-known master name; closeAfter simulates the sentinel
// dropping the connection mid-protocol.
func buildMockReply(cmd []string) (reply string, closeAfter bool) {
	// Redis commands are case-insensitive and go-redis sends them in
	// lowercase; the well-known master names in the SENTINEL argument stay
	// case-sensitive like real master group names.
	cmd = slices.Clone(cmd)
	cmd[0] = strings.ToUpper(cmd[0])
	if len(cmd) > 1 && cmd[0] == "SENTINEL" {
		cmd[1] = strings.ToLower(cmd[1])
	}

	switch {
	case len(cmd) == 1 && cmd[0] == "ROLE":
		reply = roleReply("master")
	case len(cmd) == 2 && cmd[0] == "AUTH":
		switch cmd[1] {
		case testPassword, testMasterPass:
			reply = "+OK\r\n"
		case "trigger-close":
			closeAfter = true
		default:
			reply = "-ERR invalid password\r\n"
		}
	case len(cmd) == 3 && cmd[0] == "AUTH":
		if cmd[1] == testUsername && (cmd[2] == testPassword || cmd[2] == testMasterPass) {
			reply = "+OK\r\n"
		} else {
			reply = "-WRONGPASS invalid username-password pair\r\n"
		}
	case len(cmd) == 3 && cmd[0] == "SENTINEL" && cmd[1] == "replicas":
		switch cmd[2] {
		case testMasterName:
			reply = respReplicas(
				// healthy: answers ROLE with "slave"
				respFieldMap("ip", "127.0.0.1", "port", strconv.Itoa(demotedMasterPort), "flags", "slave"),
				// healthy: second replica, link status explicitly ok
				respFieldMap("ip", "127.0.0.1", "port", strconv.Itoa(secondReplicaPort), "flags", "slave", "master-link-status", "ok"),
				// flagged subjectively down by sentinel: skipped without probing
				respFieldMap("ip", "127.0.0.1", "port", strconv.Itoa(unusedServerPort), "flags", "slave,s_down"),
				// broken replication link: skipped without probing
				respFieldMap("ip", "127.0.0.1", "port", strconv.Itoa(unusedServerPort), "flags", "slave", "master-link-status", "err"),
				// looks healthy to sentinel but reports ROLE "master": skipped by the probe
				respFieldMap("ip", "127.0.0.1", "port", strconv.Itoa(mockServerPort), "flags", "slave"),
			)
		default:
			reply = respReplicas()
		}
	case len(cmd) == 3 && cmd[0] == "SENTINEL" && cmd[1] == "get-master-addr-by-name":
		switch cmd[2] {
		case testMasterName:
			reply = respAddress("127.0.0.1", mockServerPort)
		case "unreachable-master":
			reply = respAddress("127.0.0.1", unusedServerPort)
		case "demoted-master":
			reply = respAddress("127.0.0.1", demotedMasterPort)
		case "tls-master":
			reply = respAddress("127.0.0.1", tlsMasterPort)
		case "hostname-master":
			reply = respAddress("localhost", mockServerPort)
		case "invalid-port-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$6\r\n999999\r\n"
		case "error-reply-master":
			reply = "-ERR overloaded\r\n"
		case "nil-bulk-master":
			reply = "$-1\r\n"
		case "weird-reply-master":
			reply = "+OK\r\n"
		case "short-array-master":
			reply = "*1\r\n$1\r\na\r\n"
		case "bad-count-master":
			reply = "*x\r\n"
		case "bad-element-type-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n+notabulk\r\n"
		case "bad-bulk-size-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$x\r\n"
		case "negative-size-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$-2\r\n"
		case "huge-size-master":
			// declared size exceeds the resolver's max accepted bulk length (4096 bytes)
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$999999\r\n"
		case "malformed-suffix-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$4\r\n1234XX"
		case "truncated-payload-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n$9\r\nshort"
			closeAfter = true
		case "truncated-master":
			reply = "*2\r\n$9\r\n127.0.0.1\r\n"
			closeAfter = true
		case "closed-immediately-master":
			closeAfter = true
		default:
			reply = "*-1\r\n"
		}
	default:
		reply = fmt.Sprintf("-ERR unknown command %q\r\n", strings.Join(cmd, " "))
	}
	return reply, closeAfter
}

func respAddress(host string, port int) string {
	portStr := strconv.Itoa(port)
	return fmt.Sprintf("*2\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n", len(host), host, len(portStr), portStr)
}

// respFieldMap encodes a flat field-name/value list as a RESP array of bulk
// strings, the shape of each element of a SENTINEL replicas reply.
func respFieldMap(pairs ...string) string {
	s := fmt.Sprintf("*%d\r\n", len(pairs))
	for _, p := range pairs {
		s += respBulkString(p)
	}
	return s
}

// respReplicas builds a SENTINEL replicas reply for the given field maps.
func respReplicas(fieldMaps ...string) string {
	return fmt.Sprintf("*%d\r\n", len(fieldMaps)) + strings.Join(fieldMaps, "")
}
