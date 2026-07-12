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

// replicaResolver is required of the resolver when the replica endpoint is
// enabled.
type replicaResolver interface {
	ReplicaAddress() (addr string, ok bool)
}

// addressRefresher is optionally implemented by the resolver; when available
// the proxy forces a re-resolve after a failed backend connection and
// retries once.
type addressRefresher interface {
	RefreshAddresses(ctx context.Context)
}

// handshakeTimeout bounds the client's TLS handshake so a stalled client
// cannot hold a goroutine indefinitely.
const handshakeTimeout = 10 * time.Second

type RedisSentinelProxy struct {
	localAddr      *net.TCPAddr // master endpoint; nil = disabled
	tlsConf        *tls.Config
	masterTLSConf  *tls.Config
	idleTimeout    time.Duration
	sem            chan struct{} // connection limit; nil = unlimited, shared by both listeners
	debug          bool
	masterResolver masterResolver
	refresher      addressRefresher // nil when the resolver can't refresh on demand

	replicaAddr           *net.TCPAddr // replica endpoint; nil = disabled
	replicaResolver       replicaResolver
	replicaFallbackMaster bool

	// router routes each command on the master endpoint individually: reads
	// to a replica, writes to the master (see routing.go).
	router bool
}

func NewRedisSentinelProxy(cfg *config.Config, mResolver masterResolver) (*RedisSentinelProxy, error) {
	var sem chan struct{}
	if *cfg.MaxConnections > 0 {
		sem = make(chan struct{}, *cfg.MaxConnections)
	}

	p := &RedisSentinelProxy{
		tlsConf:        cfg.ListenTLSConfig(),
		masterTLSConf:  cfg.MasterTLSConfig(),
		idleTimeout:    time.Duration(*cfg.IdleTimeout),
		sem:            sem,
		debug:          *cfg.Debug,
		masterResolver: mResolver,
	}
	p.refresher, _ = mResolver.(addressRefresher)

	var err error
	if cfg.Listen != nil && *cfg.Listen != "" {
		p.localAddr, err = net.ResolveTCPAddr("tcp", *cfg.Listen)
		if err != nil {
			return nil, fmt.Errorf("failed resolving listen address: %w", err)
		}
	}

	if cfg.ReplicaListen != nil && *cfg.ReplicaListen != "" {
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

	if p.localAddr == nil && p.replicaAddr == nil {
		return nil, fmt.Errorf("no endpoint configured: set listen and/or replica_listen")
	}

	if cfg.Router != nil && *cfg.Router {
		if p.localAddr == nil {
			return nil, fmt.Errorf("router mode requires the master endpoint (listen)")
		}
		rResolver, ok := mResolver.(replicaResolver)
		if !ok {
			return nil, fmt.Errorf("resolver does not support replica tracking")
		}
		p.replicaResolver = rResolver
		p.router = true
	}

	return p, nil
}

// pickBackend returns the backend address for a new client connection plus a
// label for logging.
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

func (r *RedisSentinelProxy) Run(ctx context.Context) (err error) {
	var listeners []net.Listener

	defer func() {
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
		}
	}()

	errGr, errCtx := errgroup.WithContext(ctx)

	if r.localAddr != nil {
		var masterListener net.Listener
		masterListener, err = net.ListenTCP("tcp", r.localAddr)
		if err != nil {
			return err
		}

		if r.tlsConf != nil {
			masterListener = tls.NewListener(masterListener, r.tlsConf)
		}

		listeners = append(listeners, masterListener)

		errGr.Go(func() error { return r.runListenLoop(errCtx, masterListener, r.pickMaster, "master", r.localAddr, r.router) })
		errGr.Go(func() error { return closeListenerByContext(errCtx, masterListener) })
	}

	if r.replicaAddr != nil {
		var replicaListener net.Listener
		replicaListener, err := net.ListenTCP("tcp", r.replicaAddr)
		if err != nil {
			return err
		}

		if r.tlsConf != nil {
			replicaListener = tls.NewListener(replicaListener, r.tlsConf)
		}

		listeners = append(listeners, replicaListener)

		errGr.Go(func() error { return r.runListenLoop(errCtx, replicaListener, r.pickReplica, "replica", r.replicaAddr, false) })
		errGr.Go(func() error { return closeListenerByContext(errCtx, replicaListener) })
	}

	return errGr.Wait()
}

func (r *RedisSentinelProxy) runListenLoop(ctx context.Context, listener net.Listener, pick pickBackend, title string, addr *net.TCPAddr, routed bool) error {
	log.Printf("Waiting for %s connections on %v ...\n", title, addr)
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
			if routed {
				r.routedProxy(ctx, conn)
			} else {
				r.proxy(ctx, conn, pick)
			}
		}()
	}
}

func (r *RedisSentinelProxy) pickAndDial(pick pickBackend) (net.Conn, string, string, error) {
	addr, label, err := pick()
	if err != nil {
		return nil, "", "", err
	}
	remote, err := r.dialRedis(addr)
	if err != nil {
		return nil, "", "", fmt.Errorf("error connecting to %s %s: %w", label, addr, err)
	}
	return remote, addr, label, nil
}

// connectBackend picks a backend and dials it. When the first attempt fails
// (stale address after a failover, or no healthy replica known), it forces a
// re-resolve and retries once before giving up on the client connection.
func (r *RedisSentinelProxy) connectBackend(ctx context.Context, pick pickBackend) (net.Conn, string, string, error) {
	remote, addr, label, err := r.pickAndDial(pick)
	if err == nil || r.refresher == nil {
		return remote, addr, label, err
	}

	log.Printf("%s; refreshing master and replica addresses and retrying", err)
	r.refresher.RefreshAddresses(ctx)
	return r.pickAndDial(pick)
}

func (r *RedisSentinelProxy) proxy(ctx context.Context, incoming net.Conn, pick pickBackend) {
	defer incoming.Close()

	if !completeClientHandshake(incoming) {
		return
	}

	remote, backendAddr, label, err := r.connectBackend(ctx, pick)
	if err != nil {
		log.Printf("Rejecting connection from %s: %s", incoming.RemoteAddr(), err)
		return
	}
	defer remote.Close()

	start := time.Now()
	if r.debug {
		log.Printf("[debug] %s: opened session to %s %s", incoming.RemoteAddr(), label, backendAddr)
	}

	sigChan := make(chan struct{})
	defer close(sigChan)

	// Both directions share one activity clock: a connection is idle only
	// when neither side sent anything (a pub/sub subscriber stays alive).
	var in, out io.Reader = incoming, remote
	if r.idleTimeout > 0 {
		activity := &atomic.Int64{}
		activity.Store(time.Now().UnixNano())
		in = &idleConn{Conn: incoming, timeout: r.idleTimeout, activity: activity}
		out = &idleConn{Conn: remote, timeout: r.idleTimeout, activity: activity}
	}

	// Byte counters only in debug mode: the wrapper defeats io.Copy's
	// zero-copy fast path (splice on Linux).
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

// countingReader counts bytes read through it; written only by the owning
// pipe goroutine and read after both pipes finished, so no synchronization.
type countingReader struct {
	io.Reader
	n *int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	*c.n += int64(n)
	return n, err
}

// idleConn enforces an idle timeout on Read, sharing the last-activity
// timestamp with the opposite direction of the session.
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
		// Keep waiting as long as the other direction saw traffic recently.
		if errors.Is(err, os.ErrDeadlineExceeded) &&
			time.Since(time.Unix(0, c.activity.Load())) < c.timeout {
			continue
		}
		return n, err
	}
}

// completeClientHandshake completes the client's TLS handshake (when the
// listener serves TLS) before any backend is dialed, so unauthenticated
// clients cannot exhaust the backend's connection limit.
func completeClientHandshake(incoming net.Conn) bool {
	if tlsConn, ok := incoming.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			log.Printf("TLS handshake with %s failed: %s", incoming.RemoteAddr(), err)
			return false
		}
	}
	return true
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

	// Half-close so the other direction can keep draining instead of racing
	// a fully-closed socket; proxy() closes both connections at the end.
	if cw, ok := w.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		w.Close()
	}

	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("Error writing content: %s", err)
	}
}
