package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/proxy"
)

const (
	backendPort          = 12710
	plainProxyPort       = 12711
	tlsProxyPort         = 12712
	tlsBackendPort       = 12717
	masterTLSProxyPort   = 12718
	passthroughProxyPort = 12719
	handshakeProxyPort   = 12720
	limitedProxyPort     = 12721
	idleProxyPort        = 12722
	handshakeBackendPort = 12723
	backendAPort         = 12724
	backendBPort         = 12725
	failoverProxyPort    = 12726
	debugProxyPort       = 12727
	debugBackendPort     = 12728
)

type stubResolver struct{ addr string }

func (s stubResolver) MasterAddress() string { return s.addr }

// atomicResolver is a masterResolver whose address can be changed while the
// proxy is running, simulating a sentinel failover.
type atomicResolver struct {
	addr atomic.Pointer[string]
}

func (r *atomicResolver) MasterAddress() string { return *r.addr.Load() }

func (r *atomicResolver) setAddr(addr string) { r.addr.Store(&addr) }

func ptr[T any](v T) *T { return &v }

// testCert is a self-signed certificate for 127.0.0.1, available both
// in-memory (for test TLS servers/clients) and as PEM files (for the
// file-based TLS options in config.Config).
type testCert struct {
	cert     tls.Certificate
	pool     *x509.CertPool
	certFile string
	keyFile  string
}

// newProxyWithResolver resolves the given partial config and creates a proxy
// using resolver. The Listen field is set from port.
func newProxyWithResolver(t *testing.T, port int, flagCfg *config.Config, resolver interface{ MasterAddress() string }) *proxy.RedisSentinelProxy {
	t.Helper()

	flagCfg.Listen = ptr(fmt.Sprintf("127.0.0.1:%d", port))
	// Tests that don't care about connection limits or idle timeouts get
	// them explicitly disabled, rather than depending on whatever
	// config.Default() happens to ship with; tests that do care about them
	// (e.g. TestMaxConnections, TestIdleTimeout) already set these fields
	// themselves, so Merge's fill-only-if-nil semantics leave them alone.
	if flagCfg.MaxConnections == nil {
		flagCfg.MaxConnections = ptr(0)
	}
	if flagCfg.IdleTimeout == nil {
		flagCfg.IdleTimeout = ptr(config.Duration(0))
	}
	cfg, err := config.Load(flagCfg, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	rsp, err := proxy.NewRedisSentinelProxy(cfg, resolver)
	if err != nil {
		t.Fatalf("NewRedisSentinelProxy() error = %v", err)
	}
	return rsp
}

// newProxyFromConfig resolves the given partial config and creates a proxy
// pointed at a fixed backend address. The Listen field is set from port.
func newProxyFromConfig(t *testing.T, port int, flagCfg *config.Config, backendAddr string) *proxy.RedisSentinelProxy {
	t.Helper()
	return newProxyWithResolver(t, port, flagCfg, stubResolver{addr: backendAddr})
}

// newProxy builds a fully resolved config for the given listen port and TLS
// sections and creates a proxy from it.
func newProxy(t *testing.T, port int, listenTLS *config.ListenTLS, masterTLS *config.BackendTLS, backendAddr string) *proxy.RedisSentinelProxy {
	t.Helper()
	return newProxyFromConfig(t, port, &config.Config{ListenTLS: listenTLS, MasterTLS: masterTLS}, backendAddr)
}

func startProxy(t *testing.T, ctx context.Context, port int, listenTLS *config.ListenTLS, masterTLS *config.BackendTLS, backendAddr string) {
	t.Helper()

	rsp := newProxy(t, port, listenTLS, masterTLS, backendAddr)
	go func() {
		if err := rsp.Run(ctx); err != nil {
			t.Errorf("proxy exited with error: %v", err)
		}
	}()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", port))
}

func TestRedisSentinelProxy(t *testing.T) {
	backendAddr := fmt.Sprintf("127.0.0.1:%d", backendPort)
	startEchoBackend(t, backendAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverCert := generateSelfSignedCert(t)

	startProxy(t, ctx, plainProxyPort, nil, nil, backendAddr)
	startProxy(t, ctx, tlsProxyPort, &config.ListenTLS{
		Enabled:  ptr(true),
		CertFile: &serverCert.certFile,
		KeyFile:  &serverCert.keyFile,
	}, nil, backendAddr)

	t.Run("plain client via plain proxy", func(t *testing.T) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", plainProxyPort))
		if err != nil {
			t.Fatalf("could not connect to proxy: %v", err)
		}
		defer conn.Close()
		checkEcho(t, conn)
	})

	t.Run("tls client via tls proxy", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsProxyPort), &tls.Config{
			RootCAs:    serverCert.pool,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("could not connect to TLS proxy: %v", err)
		}
		defer conn.Close()
		checkEcho(t, conn)
	})

	t.Run("plain client via tls proxy fails", func(t *testing.T) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsProxyPort))
		if err != nil {
			t.Fatalf("could not connect to TLS proxy: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("hello\n")); err != nil {
			return // already rejected, fine
		}
		if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
			t.Error("expected plaintext connection to a TLS listener to fail")
		}
	})
}

// TestProxyMasterTLS covers the two ways of reaching a TLS-only master: the
// proxy originating TLS itself (master TLS config set) and a raw pass-through
// pipe where the client does the TLS handshake end-to-end with the master.
func TestProxyMasterTLS(t *testing.T) {
	backendCert := generateSelfSignedCert(t)
	tlsBackendAddr := fmt.Sprintf("127.0.0.1:%d", tlsBackendPort)
	startTLSEchoBackend(t, tlsBackendAddr, backendCert.cert)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The backend's own certificate file doubles as the CA bundle.
	startProxy(t, ctx, masterTLSProxyPort, nil, &config.BackendTLS{
		CAFile: &backendCert.certFile,
	}, tlsBackendAddr)
	startProxy(t, ctx, passthroughProxyPort, nil, nil, tlsBackendAddr)

	t.Run("proxy originates TLS to master", func(t *testing.T) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", masterTLSProxyPort))
		if err != nil {
			t.Fatalf("could not connect to proxy: %v", err)
		}
		defer conn.Close()
		checkEcho(t, conn)
	})

	t.Run("client TLS passes through plain proxy to master", func(t *testing.T) {
		conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", passthroughProxyPort), &tls.Config{
			RootCAs:    backendCert.pool,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("could not handshake through the proxy: %v", err)
		}
		defer conn.Close()
		checkEcho(t, conn)
	})
}

// TestNoMasterDialBeforeHandshake ensures a client that never completes the
// TLS handshake does not cause a connection to the master, so unauthenticated
// clients cannot exhaust the master's connection limit.
func TestNoMasterDialBeforeHandshake(t *testing.T) {
	backendAddr := fmt.Sprintf("127.0.0.1:%d", handshakeBackendPort)
	accepted := startCountingBackend(t, backendAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverCert := generateSelfSignedCert(t)
	startProxy(t, ctx, handshakeProxyPort, &config.ListenTLS{
		Enabled:  ptr(true),
		CertFile: &serverCert.certFile,
		KeyFile:  &serverCert.keyFile,
	}, nil, backendAddr)

	// Speak plaintext garbage at the TLS listener: the handshake fails, so
	// the proxy must drop the client without ever dialing the master.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", handshakeProxyPort))
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte("definitely not a TLS client hello\n"))
	buf := make([]byte, 1)
	conn.Read(buf) // wait until the proxy closes the connection

	// The handshake failure above is synchronous with the close we just
	// observed, so any (wrong) master dial would already have happened.
	time.Sleep(100 * time.Millisecond)
	if got := accepted.Load(); got != 0 {
		t.Errorf("master received %d connection(s) from an unauthenticated client, want 0", got)
	}
}

func TestMaxConnections(t *testing.T) {
	backendAddr := fmt.Sprintf("127.0.0.1:%d", backendPort)
	startEchoBackend(t, backendAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rsp := newProxyFromConfig(t, limitedProxyPort, &config.Config{MaxConnections: ptr(1)}, backendAddr)
	go rsp.Run(ctx)
	addr := fmt.Sprintf("127.0.0.1:%d", limitedProxyPort)
	waitForListener(t, addr)

	// The waitForListener probe above may still hold the single slot for a
	// moment, so retry until this client owns it (verified by a working echo).
	first := dialEcho(t, addr)
	defer first.Close()

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("could not connect second client: %v", err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := second.Read(buf); err == nil {
		t.Error("expected the second connection to be rejected while the limit is reached")
	}

	// Releasing the first connection frees the slot for a new client.
	first.Close()
	third := dialEcho(t, addr)
	third.Close()
}

// dialEcho connects to the proxy and verifies a round trip, retrying until
// a connection slot is available.
func dialEcho(t *testing.T, addr string) net.Conn {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		msg := "ping\n"
		if _, err := conn.Write([]byte(msg)); err == nil {
			if got, err := bufio.NewReader(conn).ReadString('\n'); err == nil && got == msg {
				conn.SetDeadline(time.Time{})
				return conn
			}
		}
		conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("could not get an echoing connection within 5s")
	return nil
}

func TestIdleTimeout(t *testing.T) {
	backendAddr := fmt.Sprintf("127.0.0.1:%d", backendPort)
	startEchoBackend(t, backendAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rsp := newProxyFromConfig(t, idleProxyPort, &config.Config{
		IdleTimeout: ptr(config.Duration(200 * time.Millisecond)),
	}, backendAddr)
	go rsp.Run(ctx)
	addr := fmt.Sprintf("127.0.0.1:%d", idleProxyPort)
	waitForListener(t, addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	defer conn.Close()

	// Activity within the timeout keeps the connection alive well past a
	// single idle window.
	for range 4 {
		time.Sleep(100 * time.Millisecond)
		checkEcho(t, conn)
	}

	// Once fully idle, the proxy must close the connection.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected the idle connection to be closed by the proxy")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Error("idle connection was not closed within 5s")
	}
}

// TestProxyFollowsMasterChange verifies the proxy behavior during a sentinel
// failover: proxy() calls MasterAddress() once per new connection, so a
// connection already in flight keeps talking to the old master, while any
// connection accepted after the switch reaches the new one.
func TestProxyFollowsMasterChange(t *testing.T) {
	addrA := fmt.Sprintf("127.0.0.1:%d", backendAPort)
	addrB := fmt.Sprintf("127.0.0.1:%d", backendBPort)
	startLabeledBackend(t, addrA, "backend-a")
	startLabeledBackend(t, addrB, "backend-b")

	resolver := &atomicResolver{}
	resolver.setAddr(addrA)

	rsp := newProxyWithResolver(t, failoverProxyPort, &config.Config{}, resolver)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rsp.Run(ctx)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", failoverProxyPort)
	waitForListener(t, proxyAddr)

	beforeSwitch, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("could not connect before switch: %v", err)
	}
	defer beforeSwitch.Close()
	beforeSwitch.SetDeadline(time.Now().Add(2 * time.Second))
	if label, err := bufio.NewReader(beforeSwitch).ReadString('\n'); err != nil || label != "backend-a\n" {
		t.Fatalf("label = %q, err = %v, want backend-a", label, err)
	}

	resolver.setAddr(addrB)

	// The already-established connection is unaffected by the switch: it
	// keeps talking to A.
	checkEcho(t, beforeSwitch)

	// A new connection opened after the switch must reach B.
	afterSwitch, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("could not connect after switch: %v", err)
	}
	defer afterSwitch.Close()
	afterSwitch.SetDeadline(time.Now().Add(2 * time.Second))
	if label, err := bufio.NewReader(afterSwitch).ReadString('\n'); err != nil || label != "backend-b\n" {
		t.Fatalf("label = %q, err = %v, want backend-b", label, err)
	}
}

func TestNewRedisSentinelProxyInvalidListenAddr(t *testing.T) {
	cfg, err := config.Load(&config.Config{Listen: ptr("not a valid addr")}, "")
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if _, err := proxy.NewRedisSentinelProxy(cfg, stubResolver{addr: "127.0.0.1:1"}); err == nil {
		t.Fatal("expected an error for an invalid listen address")
	}
}

func TestRunListenTCPFails(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12713}

	blocker, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("could not bind blocking listener: %v", err)
	}
	defer blocker.Close()

	rsp := newProxy(t, addr.Port, nil, nil, "127.0.0.1:1")
	if err := rsp.Run(context.Background()); err == nil {
		t.Fatal("expected an error when the listen address is already in use")
	}
}

func TestRunReturnsPromptlyWhenContextAlreadyCancelled(t *testing.T) {
	rsp := newProxy(t, 12714, nil, nil, "127.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- rsp.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return promptly for an already-cancelled context")
	}
}

func TestRunStopsAcceptingOnContextCancel(t *testing.T) {
	rsp := newProxy(t, 12715, nil, nil, "127.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- rsp.Run(ctx) }()
	waitForListener(t, "127.0.0.1:12715")

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run() error = %v, want nil after context cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after context cancel")
	}
}

func TestProxyClosesClientWhenMasterUnreachable(t *testing.T) {
	// Nothing listens here, so proxy() should fail to reach the "master"
	// and close the incoming connection instead of echoing anything.
	rsp := newProxy(t, 12716, nil, nil, "127.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rsp.Run(ctx)
	waitForListener(t, "127.0.0.1:12716")

	conn, err := net.Dial("tcp", "127.0.0.1:12716")
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Error("expected the client connection to be closed when the master is unreachable")
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent log writes and reads.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestDebugLogging verifies that with the debug option enabled the proxy logs
// the session lifecycle including the per-direction byte counts.
func TestDebugLogging(t *testing.T) {
	backendAddr := fmt.Sprintf("127.0.0.1:%d", debugBackendPort)
	startEchoBackend(t, backendAddr)

	var logBuf syncBuffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	rsp := newProxyWithResolver(t, debugProxyPort, &config.Config{Debug: ptr(true)}, stubResolver{addr: backendAddr})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := rsp.Run(ctx); err != nil {
			t.Errorf("proxy exited with error: %v", err)
		}
	}()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", debugProxyPort))

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", debugProxyPort))
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	checkEcho(t, conn) // sends a 24-byte line and reads it back
	conn.Close()

	// The "closed session" line is written asynchronously once both pipe
	// directions have finished, so poll for it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		out := logBuf.String()
		if strings.Contains(out, "opened session to master "+backendAddr) &&
			strings.Contains(out, "closed session to master "+backendAddr) &&
			strings.Contains(out, "client->master 24 bytes, master->client 24 bytes") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("debug session logs not found in log output:\n%s", out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startEchoBackend(t *testing.T, addr string) {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not start echo backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go acceptAndEcho(listener)
}

func startTLSEchoBackend(t *testing.T, addr string, cert tls.Certificate) {
	t.Helper()

	listener, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("could not start TLS echo backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go acceptAndEcho(listener)
}

// startCountingBackend is an echo backend that counts accepted connections.
func startCountingBackend(t *testing.T, addr string) *atomic.Int64 {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not start counting backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return &accepted
}

// startLabeledBackend is an echo backend that first writes label+"\n" to
// every new connection, so a test can tell which backend served a given
// connection before exchanging any further traffic.
func startLabeledBackend(t *testing.T, addr, label string) {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not start labeled backend %s: %v", label, err)
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
				if _, err := c.Write([]byte(label + "\n")); err != nil {
					return
				}
				io.Copy(c, c)
			}(conn)
		}
	}()
}

func acceptAndEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(conn)
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener on %s did not come up", addr)
}

func checkEcho(t *testing.T, conn net.Conn) {
	t.Helper()

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	msg := "hello through the proxy\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("could not write to proxy: %v", err)
	}
	got, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("could not read echo: %v", err)
	}
	if got != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

func generateSelfSignedCert(t *testing.T) testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-proxy"},
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
	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("could not marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("could not write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("could not write key file: %v", err)
	}

	return testCert{
		cert:     tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf},
		pool:     pool,
		certFile: certFile,
		keyFile:  keyFile,
	}
}
