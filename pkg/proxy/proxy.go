// cspell:words errgroup
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/utils"
	"golang.org/x/sync/errgroup"
)

type masterResolver interface {
	MasterAddress() string
}

// replicaResolver is the additional capability the resolver must provide
// when the replica endpoint is enabled.
type replicaResolver interface {
	ReplicaAddress() (addr string, ok bool)
}

// handshakeTimeout bounds the client's TLS handshake so a client that
// connects and stalls cannot hold a goroutine indefinitely.
const handshakeTimeout = 10 * time.Second

type RedisSentinelProxy struct {
	localAddr      *net.TCPAddr
	tlsConf        *tls.Config
	masterTLSConf  *tls.Config
	idleTimeout    time.Duration
	sem            chan struct{} // connection-limit semaphore; nil = unlimited, shared by both listeners
	debug          bool
	masterResolver masterResolver

	// Replica endpoint; replicaAddr == nil means disabled.
	replicaAddr           *net.TCPAddr
	replicaResolver       replicaResolver
	replicaFallbackMaster bool
}

func NewRedisSentinelProxy(cfg *config.Config, mResolver masterResolver) (*RedisSentinelProxy, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", *cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("failed resolving listen address: %w", err)
	}

	var sem chan struct{}
	if *cfg.MaxConnections > 0 {
		sem = make(chan struct{}, *cfg.MaxConnections)
	}

	p := &RedisSentinelProxy{
		localAddr:      tcpAddr,
		tlsConf:        cfg.ListenTLSConfig(),
		masterTLSConf:  cfg.MasterTLSConfig(),
		idleTimeout:    time.Duration(*cfg.IdleTimeout),
		sem:            sem,
		debug:          *cfg.Debug,
		masterResolver: mResolver,
	}

	if *cfg.ReplicaListen != "" {
		p.replicaAddr, err = net.ResolveTCPAddr("tcp", *cfg.ReplicaListen)
		if err != nil {
			return nil, fmt.Errorf("failed resolving replica listen address: %w", err)
		}
		rResolver, ok := mResolver.(replicaResolver)
		if !ok {
			return nil, fmt.Errorf("resolver does not support replica tracking")
		}
		p.replicaResolver = rResolver
		p.replicaFallbackMaster = *cfg.ReplicaFallback == config.ReplicaFallbackMaster
	}

	return p, nil
}

// pickBackend returns the address a new client connection should be proxied
// to, together with a label for logging ("master" or "replica").
type pickBackend func() (addr string, label string, err error)

func (r *RedisSentinelProxy) pickMaster() (string, string, error) {
	return r.masterResolver.MasterAddress(), "master", nil
}

func (r *RedisSentinelProxy) pickReplica() (string, string, error) {
	if addr, ok := r.replicaResolver.ReplicaAddress(); ok {
		return addr, "replica", nil
	}
	if r.replicaFallbackMaster {
		return r.masterResolver.MasterAddress(), "master (replica fallback)", nil
	}
	return "", "", fmt.Errorf("no healthy replica available")
}

func (r *RedisSentinelProxy) Run(bigCtx context.Context) error {
	var listener net.Listener
	listener, err := net.ListenTCP("tcp", r.localAddr)
	if err != nil {
		return err
	}
	if r.tlsConf != nil {
		listener = tls.NewListener(listener, r.tlsConf)
	}

	errGr, ctx := errgroup.WithContext(bigCtx)
	errGr.Go(func() error { return r.runListenLoop(ctx, listener, r.pickMaster) })
	errGr.Go(func() error { return closeListenerByContext(ctx, listener) })

	if r.replicaAddr != nil {
		var replicaListener net.Listener
		replicaListener, err := net.ListenTCP("tcp", r.replicaAddr)
		if err != nil {
			listener.Close()
			return err
		}
		if r.tlsConf != nil {
			replicaListener = tls.NewListener(replicaListener, r.tlsConf)
		}
		errGr.Go(func() error { return r.runListenLoop(ctx, replicaListener, r.pickReplica) })
		errGr.Go(func() error { return closeListenerByContext(ctx, replicaListener) })
	}

	return errGr.Wait()
}

func (r *RedisSentinelProxy) runListenLoop(ctx context.Context, listener net.Listener, pick pickBackend) error {
	log.Println("Waiting for connections...")
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Println(err)
			// Avoid a busy loop on persistent accept errors (e.g. EMFILE).
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if r.sem != nil {
			select {
			case r.sem <- struct{}{}:
			default:
				log.Printf("Rejecting connection from %s: connection limit reached", conn.RemoteAddr())
				conn.Close()
				continue
			}
		}

		go func() {
			defer func() {
				if r.sem != nil {
					<-r.sem
				}
			}()
			r.proxy(conn, pick)
		}()
	}
}

func (r *RedisSentinelProxy) proxy(incoming net.Conn, pick pickBackend) {
	defer incoming.Close()

	// Complete the client's TLS handshake (including client-certificate
	// verification when a client CA is configured) before opening a
	// connection to the backend, so unauthenticated clients cannot exhaust
	// the backend's connection limit.
	if tlsConn, ok := incoming.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			log.Printf("TLS handshake with %s failed: %s", incoming.RemoteAddr(), err)
			return
		}
	}

	backendAddr, label, err := pick()
	if err != nil {
		log.Printf("Rejecting connection from %s: %s", incoming.RemoteAddr(), err)
		return
	}
	remote, err := r.dialRedis(backendAddr)
	if err != nil {
		log.Printf("Error connecting to %s: %s", label, err)
		return
	}
	defer remote.Close()

	start := time.Now()
	if r.debug {
		log.Printf("[debug] %s: opened session to %s %s", incoming.RemoteAddr(), label, backendAddr)
	}

	sigChan := make(chan struct{})
	defer close(sigChan)

	// Both directions share one activity clock, so a connection only counts
	// as idle when neither side has sent anything for the whole timeout
	// (e.g. a pub/sub subscriber that never writes stays alive).
	var in, out io.Reader = incoming, remote
	if r.idleTimeout > 0 {
		activity := &atomic.Int64{}
		activity.Store(time.Now().UnixNano())
		in = &idleConn{Conn: incoming, timeout: r.idleTimeout, activity: activity}
		out = &idleConn{Conn: remote, timeout: r.idleTimeout, activity: activity}
	}

	// Byte counters are debug-only: the wrapper would otherwise defeat
	// io.Copy's zero-copy fast path (splice on Linux) on raw TCP connections.
	var sent, received int64
	if r.debug {
		in = &countingReader{Reader: in, n: &sent}
		out = &countingReader{Reader: out, n: &received}
	}

	go pipe(incoming, out, sigChan)
	go pipe(remote, in, sigChan)

	<-sigChan
	<-sigChan

	if r.debug {
		log.Printf("[debug] %s: closed session to %s %s after %s (client->backend %d bytes, backend->client %d bytes)",
			incoming.RemoteAddr(), label, backendAddr, time.Since(start).Round(time.Millisecond), sent, received)
	}
}

// countingReader counts the bytes read through it. The counter is written
// only by the pipe goroutine owning this direction and read by proxy() after
// both pipes have signalled completion, so it needs no synchronization of
// its own.
type countingReader struct {
	io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	*c.n += int64(n)
	return n, err
}

// idleConn enforces an idle timeout on Read while sharing the last-activity
// timestamp with the opposite direction of the same proxied session.
type idleConn struct {
	net.Conn
	timeout  time.Duration
	activity *atomic.Int64
}

func (c *idleConn) Read(p []byte) (int, error) {
	for {
		if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return 0, err
		}
		n, err := c.Conn.Read(p)
		if n > 0 {
			c.activity.Store(time.Now().UnixNano())
		}
		// On a deadline hit, keep waiting as long as the other direction
		// has seen traffic within the timeout window.
		if errors.Is(err, os.ErrDeadlineExceeded) &&
			time.Since(time.Unix(0, c.activity.Load())) < c.timeout {
			continue
		}
		return n, err
	}
}

func (r *RedisSentinelProxy) dialRedis(addr string) (net.Conn, error) {
	if r.masterTLSConf == nil {
		return utils.TCPConnectWithTimeout(addr)
	}
	return utils.TLSConnectWithTimeout(addr, r.masterTLSConf)
}

func closeListenerByContext(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	<-ctx.Done()
	return nil
}

func pipe(w io.WriteCloser, r io.Reader, sigChan chan<- struct{}) {
	defer func() { sigChan <- struct{}{} }()

	_, err := io.Copy(w, r)

	// Half-close so the sibling goroutine copying the other direction can
	// keep draining instead of racing a fully-closed socket (the source of
	// "use of closed network connection" log spam on short-lived clients,
	// e.g. Kubernetes probes). proxy() fully closes both connections once
	// both directions have finished.
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		w.Close()
	}

	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("Error writing content: %s", err)
	}
}
