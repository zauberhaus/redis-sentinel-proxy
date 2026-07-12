package proxy_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/proxy"
)

const (
	routerMasterPort      = 12744
	routerReplicaPort     = 12745
	routerProxyPort       = 12746
	routerSoloProxyPort   = 12747
	routerInlineMaster    = 12748
	routerInlineReplica   = 12749
	routerInlineProxy     = 12750
	routerDeadReplicaPort = 12751
	routerFallbackMaster  = 12752
	routerFallbackProxy   = 12753
	routerRefreshMaster   = 12754
	routerRefreshReplica  = 12755
	routerRefreshProxy    = 12756
	routerDeadMasterPort  = 12757
	routerDeadMasterProxy = 12758
)

// commandLog records the commands a fake backend received.
type commandLog struct {
	mu   sync.Mutex
	cmds []string
}

func (l *commandLog) add(cmd string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cmds = append(l.cmds, cmd)
}

func (l *commandLog) commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.cmds)
}

// startRESPBackend starts a minimal RESP server answering every command with
// "+<label>:<COMMAND>", so tests can see which backend served it.
func startRESPBackend(t *testing.T, addr, label string) *commandLog {
	t.Helper()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("could not start fake backend: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	logged := &commandLog{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serveRESP(conn, label, logged)
		}
	}()
	return logged
}

func serveRESP(conn net.Conn, label string, logged *commandLog) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	for {
		args, err := readRESPCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		name := strings.ToUpper(args[0])
		logged.add(name)
		fmt.Fprintf(conn, "+%s:%s\r\n", label, name)
	}
}

func readRESPCommand(br *bufio.Reader) ([]string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(line, "*") {
		return strings.Fields(line), nil // inline command
	}
	n, err := strconv.Atoi(strings.TrimSpace(line[1:]))
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, n)
	for range n {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		l, err := strconv.Atoi(strings.TrimSpace(lenLine[1:]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, l+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:l]))
	}
	return args, nil
}

// sendCommand writes one RESP command and returns the single-line reply.
func sendCommand(t *testing.T, conn net.Conn, br *bufio.Reader, args ...string) string {
	t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := conn.Write([]byte(b.String())); err != nil {
		t.Fatalf("writing %v: %v", args, err)
	}
	reply, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("reading reply to %v: %v", args, err)
	}
	return strings.TrimSpace(reply)
}

func TestRouterMode(t *testing.T) {
	masterAddr := fmt.Sprintf("127.0.0.1:%d", routerMasterPort)
	replicaAddr := fmt.Sprintf("127.0.0.1:%d", routerReplicaPort)
	masterLog := startRESPBackend(t, masterAddr, "master")
	replicaLog := startRESPBackend(t, replicaAddr, "replica")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &stubReplicaResolver{master: masterAddr, replicas: []string{replicaAddr}}
	rsp := newProxyWithResolver(t, routerProxyPort, &config.Config{Router: ptr(true)}, resolver)
	go func() {
		if err := rsp.Run(ctx); err != nil {
			t.Errorf("proxy exited with error: %v", err)
		}
	}()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", routerProxyPort))

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", routerProxyPort))
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	if got := sendCommand(t, conn, br, "SET", "k", "v"); got != "+master:SET" {
		t.Errorf("SET served by %q, want the master", got)
	}
	if got := sendCommand(t, conn, br, "GET", "k"); got != "+replica:GET" {
		t.Errorf("GET served by %q, want the replica", got)
	}
	if got := sendCommand(t, conn, br, "JSON.GET", "k"); got != "+replica:JSON.GET" {
		t.Errorf("JSON.GET served by %q, want the replica", got)
	}
	if got := sendCommand(t, conn, br, "SOMEFUTURECMD"); got != "+master:SOMEFUTURECMD" {
		t.Errorf("unknown command served by %q, want the master", got)
	}

	// Connection state goes to both backends; the client sees the master's reply.
	if got := sendCommand(t, conn, br, "SELECT", "1"); got != "+master:SELECT" {
		t.Errorf("SELECT answered by %q, want the master", got)
	}
	if cmds := replicaLog.commands(); !slices.Contains(cmds, "SELECT") {
		t.Errorf("replica commands = %v, want SELECT forwarded", cmds)
	}

	// SUBSCRIBE pins the session to the master; later reads stay there.
	if got := sendCommand(t, conn, br, "SUBSCRIBE", "chan"); got != "+master:SUBSCRIBE" {
		t.Errorf("SUBSCRIBE served by %q, want the master", got)
	}
	if got := sendCommand(t, conn, br, "GET", "k"); got != "+master:GET" {
		t.Errorf("GET after SUBSCRIBE served by %q, want the pinned master", got)
	}

	if cmds := masterLog.commands(); slices.Contains(cmds, "JSON.GET") {
		t.Errorf("master commands = %v, JSON.GET should have gone to the replica", cmds)
	}
	if cmds := replicaLog.commands(); slices.Contains(cmds, "SET") {
		t.Errorf("replica commands = %v, SET should have gone to the master", cmds)
	}
}

// startRoutedProxy starts a router-mode proxy on port using resolver and
// returns a helper dialing new client connections to it.
func startRoutedProxy(t *testing.T, ctx context.Context, port int, resolver interface{ MasterAddress() string }) func() (net.Conn, *bufio.Reader) {
	t.Helper()

	rsp := newProxyWithResolver(t, port, &config.Config{Router: ptr(true)}, resolver)
	go func() {
		if err := rsp.Run(ctx); err != nil {
			t.Errorf("proxy exited with error: %v", err)
		}
	}()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitForListener(t, addr)

	return func() (net.Conn, *bufio.Reader) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("could not connect to proxy: %v", err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn, bufio.NewReader(conn)
	}
}

// TestRouterModeInlineAndEmpty covers the protocol edge cases: an empty
// array is a no-op, and an inline (telnet-style) client degrades the session
// to a plain pipe to the master.
func TestRouterModeInlineAndEmpty(t *testing.T) {
	masterAddr := fmt.Sprintf("127.0.0.1:%d", routerInlineMaster)
	replicaAddr := fmt.Sprintf("127.0.0.1:%d", routerInlineReplica)
	masterLog := startRESPBackend(t, masterAddr, "master")
	startRESPBackend(t, replicaAddr, "replica")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &stubReplicaResolver{master: masterAddr, replicas: []string{replicaAddr}}
	dial := startRoutedProxy(t, ctx, routerInlineProxy, resolver)

	t.Run("empty array is a no-op", func(t *testing.T) {
		conn, br := dial()
		if _, err := conn.Write([]byte("*0\r\n")); err != nil {
			t.Fatalf("writing empty array: %v", err)
		}
		if got := sendCommand(t, conn, br, "GET", "k"); got != "+replica:GET" {
			t.Errorf("GET after empty array served by %q, want the replica", got)
		}
	})

	t.Run("inline protocol falls back to a master pipe", func(t *testing.T) {
		conn, br := dial()
		if _, err := conn.Write([]byte("PING\r\n")); err != nil {
			t.Fatalf("writing inline command: %v", err)
		}
		reply, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading inline reply: %v", err)
		}
		if got := strings.TrimSpace(reply); got != "+master:PING" {
			t.Errorf("inline PING served by %q, want the master", got)
		}
		// The pinned pipe keeps serving everything, including reads.
		if got := sendCommand(t, conn, br, "GET", "k"); got != "+master:GET" {
			t.Errorf("GET on inline session served by %q, want the pinned master", got)
		}
	})

	if cmds := masterLog.commands(); slices.Contains(cmds, "") {
		t.Errorf("master commands = %v, the empty array must not be forwarded", cmds)
	}
}

// TestRouterModeReplicaDialFailure checks that a known but unreachable
// replica degrades the session to master-only instead of failing it.
func TestRouterModeReplicaDialFailure(t *testing.T) {
	masterAddr := fmt.Sprintf("127.0.0.1:%d", routerFallbackMaster)
	startRESPBackend(t, masterAddr, "master")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadReplica := fmt.Sprintf("127.0.0.1:%d", routerDeadReplicaPort)
	resolver := &stubReplicaResolver{master: masterAddr, replicas: []string{deadReplica}}
	dial := startRoutedProxy(t, ctx, routerFallbackProxy, resolver)

	conn, br := dial()
	if got := sendCommand(t, conn, br, "GET", "k"); got != "+master:GET" {
		t.Errorf("GET with unreachable replica served by %q, want the master", got)
	}
}

// TestRouterModeReplicaRefresh checks that a session with no known replica
// triggers an on-demand re-resolve and then uses the discovered replica.
func TestRouterModeReplicaRefresh(t *testing.T) {
	masterAddr := fmt.Sprintf("127.0.0.1:%d", routerRefreshMaster)
	replicaAddr := fmt.Sprintf("127.0.0.1:%d", routerRefreshReplica)
	startRESPBackend(t, masterAddr, "master")
	startRESPBackend(t, replicaAddr, "replica")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &refreshingReplicaResolver{master: masterAddr, fresh: replicaAddr}
	dial := startRoutedProxy(t, ctx, routerRefreshProxy, resolver)

	conn, br := dial()
	if got := sendCommand(t, conn, br, "GET", "k"); got != "+replica:GET" {
		t.Errorf("GET after replica refresh served by %q, want the replica", got)
	}
}

// TestRouterModeMasterUnreachable checks that a dead master rejects the
// client connection like the pipe mode does.
func TestRouterModeMasterUnreachable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	deadMaster := fmt.Sprintf("127.0.0.1:%d", routerDeadMasterPort)
	resolver := &stubReplicaResolver{master: deadMaster}
	dial := startRoutedProxy(t, ctx, routerDeadMasterProxy, resolver)

	conn, br := dial()
	conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	if _, err := br.ReadString('\n'); err == nil {
		t.Error("expected the connection to be closed when the master is unreachable")
	}
}

func TestNewRedisSentinelProxyRouterValidation(t *testing.T) {
	t.Run("router requires the master endpoint", func(t *testing.T) {
		cfg, err := config.Load(&config.Config{
			Router:        ptr(true),
			ReplicaListen: ptr("127.0.0.1:0"),
		}, "")
		if err != nil {
			t.Fatalf("config.Load() error = %v", err)
		}
		if _, err := proxy.NewRedisSentinelProxy(cfg, &stubReplicaResolver{master: "127.0.0.1:1"}); err == nil {
			t.Error("expected error for router mode without the master endpoint")
		}
	})

	t.Run("router requires replica tracking", func(t *testing.T) {
		cfg, err := config.Load(&config.Config{
			Router: ptr(true),
			Listen: ptr("127.0.0.1:0"),
		}, "")
		if err != nil {
			t.Fatalf("config.Load() error = %v", err)
		}
		if _, err := proxy.NewRedisSentinelProxy(cfg, stubResolver{addr: "127.0.0.1:1"}); err == nil {
			t.Error("expected error for a resolver without replica tracking")
		}
	})
}

// TestRouterModeWithoutReplica checks the degraded mode: with no healthy
// replica known, every command is served by the master.
func TestRouterModeWithoutReplica(t *testing.T) {
	masterAddr := fmt.Sprintf("127.0.0.1:%d", routerMasterPort)
	startRESPBackend(t, masterAddr, "solo")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := &stubReplicaResolver{master: masterAddr}
	rsp := newProxyWithResolver(t, routerSoloProxyPort, &config.Config{Router: ptr(true)}, resolver)
	go func() {
		if err := rsp.Run(ctx); err != nil {
			t.Errorf("proxy exited with error: %v", err)
		}
	}()
	waitForListener(t, fmt.Sprintf("127.0.0.1:%d", routerSoloProxyPort))

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", routerSoloProxyPort))
	if err != nil {
		t.Fatalf("could not connect to proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	if got := sendCommand(t, conn, br, "GET", "k"); got != "+solo:GET" {
		t.Errorf("GET served by %q, want the master", got)
	}
	if got := sendCommand(t, conn, br, "SET", "k", "v"); got != "+solo:SET" {
		t.Errorf("SET served by %q, want the master", got)
	}
}
