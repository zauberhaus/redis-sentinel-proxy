package utils

import (
	"crypto/tls"
	"net"
	"time"
)

func TCPConnectWithTimeout(addr string) (net.Conn, error) {
	remote, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	return remote, nil
}

// TLSConnectWithTimeout dials addr and performs a TLS handshake, all within
// the same one-second timeout used for plain TCP connections.
func TLSConnectWithTimeout(addr string, tlsConf *tls.Config) (net.Conn, error) {
	return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", addr, tlsConf)
}
