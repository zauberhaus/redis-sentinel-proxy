package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/router"
)

// Router mode: instead of piping bytes, the session parses the RESP protocol
// and routes every command individually — reads to a replica, writes and
// unknown commands to the master. Each client connection holds one master
// and (when a healthy replica is known) one replica connection.

// stateCommands change per-connection state and are therefore sent to both
// backends so they stay in sync; the client sees the master's reply.
var stateCommands = map[string]struct{}{
	"AUTH": {}, "HELLO": {}, "SELECT": {}, "RESET": {}, "CLIENT": {},
}

// pinCommands start a conversation that cannot be routed per command
// (subscriptions, transactions, monitoring). They pin the session to the
// master: the command is forwarded and the session degrades to a plain pipe.
var pinCommands = map[string]struct{}{
	"SUBSCRIBE": {}, "PSUBSCRIBE": {}, "SSUBSCRIBE": {},
	"UNSUBSCRIBE": {}, "PUNSUBSCRIBE": {}, "SUNSUBSCRIBE": {},
	"MULTI": {}, "WATCH": {}, "MONITOR": {},
}

type routedSession struct {
	client  net.Conn
	clientR *bufio.Reader

	master  net.Conn
	masterR *bufio.Reader

	// nil when no healthy replica was available; reads then go to the master.
	replica  net.Conn
	replicaR *bufio.Reader

	reads, writes int64
}

func (r *RedisSentinelProxy) routedProxy(ctx context.Context, incoming net.Conn) {
	defer incoming.Close()

	if !completeClientHandshake(incoming) {
		return
	}

	master, masterAddr, _, err := r.connectBackend(ctx, r.pickMaster)
	if err != nil {
		log.Printf("Rejecting connection from %s: %s", incoming.RemoteAddr(), err)
		return
	}
	defer master.Close()

	replica, replicaAddr := r.dialReplicaForRouting(ctx)
	if replica != nil {
		defer replica.Close()
	}

	// All three connections share one activity clock, like the pipe mode: the
	// session is idle only when nobody sent anything.
	var clientIn, masterIn, replicaIn io.Reader = incoming, master, nil
	if replica != nil {
		replicaIn = replica
	}
	if r.idleTimeout > 0 {
		activity := &atomic.Int64{}
		activity.Store(time.Now().UnixNano())
		clientIn = &idleConn{Conn: incoming, timeout: r.idleTimeout, activity: activity}
		masterIn = &idleConn{Conn: master, timeout: r.idleTimeout, activity: activity}
		if replica != nil {
			replicaIn = &idleConn{Conn: replica, timeout: r.idleTimeout, activity: activity}
		}
	}

	s := &routedSession{
		client:  incoming,
		clientR: bufio.NewReader(clientIn),
		master:  master,
		masterR: bufio.NewReader(masterIn),
	}
	if replica != nil {
		s.replica = replica
		s.replicaR = bufio.NewReader(replicaIn)
	}

	start := time.Now()
	if r.debug {
		if replica != nil {
			log.Printf("[debug] %s: opened routed session (master %s, replica %s)", incoming.RemoteAddr(), masterAddr, replicaAddr)
		} else {
			log.Printf("[debug] %s: opened routed session (master %s, no replica)", incoming.RemoteAddr(), masterAddr)
		}
	}

	s.run()

	if r.debug {
		log.Printf("[debug] %s: closed routed session after %s (%d reads, %d writes)",
			incoming.RemoteAddr(), time.Since(start).Round(time.Millisecond), s.reads, s.writes)
	}
}

// dialReplicaForRouting connects to a healthy replica for a routed session.
// Every failure degrades gracefully to nil: reads are then served by the
// master, which is always correct.
func (r *RedisSentinelProxy) dialReplicaForRouting(ctx context.Context) (net.Conn, string) {
	addr, ok := r.replicaResolver.ReplicaAddress()
	if !ok && r.refresher != nil {
		r.refresher.RefreshAddresses(ctx)
		addr, ok = r.replicaResolver.ReplicaAddress()
	}
	if !ok {
		return nil, ""
	}
	conn, err := r.dialRedis(addr)
	if err != nil {
		log.Printf("error connecting to replica %s, serving reads from the master: %s", addr, err)
		return nil, ""
	}
	return conn, addr
}

func (s *routedSession) run() {
	for {
		name, raw, err := readCommand(s.clientR)
		if errors.Is(err, errInlineCommand) {
			// Inline (telnet-style) protocol: no framing to route on.
			s.pin(nil)
			return
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("Error reading client command from %s: %s", s.client.RemoteAddr(), err)
			}
			return
		}
		if name == "" { // empty array, a client no-op
			continue
		}

		if _, ok := pinCommands[name]; ok {
			s.pin(raw)
			return
		}

		if _, ok := stateCommands[name]; ok {
			if err := s.stateCommand(raw); err != nil {
				log.Printf("Error forwarding %s for %s: %s", name, s.client.RemoteAddr(), err)
				return
			}
			continue
		}

		backend, backendR := s.master, s.masterR
		if s.replica != nil && router.GetDirection(name) == router.Read {
			backend, backendR = s.replica, s.replicaR
			s.reads++
		} else {
			s.writes++
		}
		if _, err := backend.Write(raw); err != nil {
			log.Printf("Error forwarding %s for %s: %s", name, s.client.RemoteAddr(), err)
			return
		}
		if err := copyRESP(s.client, backendR); err != nil {
			log.Printf("Error relaying %s reply for %s: %s", name, s.client.RemoteAddr(), err)
			return
		}
	}
}

// stateCommand forwards raw to both backends, relays the master's reply to
// the client and discards the replica's.
func (s *routedSession) stateCommand(raw []byte) error {
	if _, err := s.master.Write(raw); err != nil {
		return err
	}
	if s.replica != nil {
		if _, err := s.replica.Write(raw); err != nil {
			return err
		}
	}
	if err := copyRESP(s.client, s.masterR); err != nil {
		return err
	}
	if s.replica != nil {
		if err := copyRESP(io.Discard, s.replicaR); err != nil {
			return err
		}
	}
	return nil
}

// pin drops the replica connection, forwards raw (if any) to the master and
// turns the rest of the session into a plain bidirectional pipe.
func (s *routedSession) pin(raw []byte) {
	if s.replica != nil {
		s.replica.Close()
		s.replica = nil
	}
	if raw != nil {
		if _, err := s.master.Write(raw); err != nil {
			log.Printf("Error forwarding command for %s: %s", s.client.RemoteAddr(), err)
			return
		}
	}

	sigChan := make(chan struct{})
	defer close(sigChan)

	// The bufio readers drain their buffered bytes before reading from the
	// (idle-timeout wrapped) connections again.
	go pipe(s.client, s.masterR, sigChan)
	go pipe(s.master, s.clientR, sigChan)

	<-sigChan
	<-sigChan
}
