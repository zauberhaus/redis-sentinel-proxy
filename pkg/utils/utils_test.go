package utils_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/utils"
)

func TestTCPConnectWithTimeout(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("could not start listener: %v", err)
		}
		defer listener.Close()

		conn, err := utils.TCPConnectWithTimeout(listener.Addr().String())
		if err != nil {
			t.Fatalf("utils.TCPConnectWithTimeout() error = %v", err)
		}
		defer conn.Close()
	})

	t.Run("connection refused", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("could not reserve a port: %v", err)
		}
		addr := listener.Addr().String()
		listener.Close() // nothing listening on addr anymore

		if _, err := utils.TCPConnectWithTimeout(addr); err == nil {
			t.Error("expected an error connecting to a closed port, got nil")
		}
	})
}

func TestTLSConnectWithTimeout(t *testing.T) {
	cert, pool := generateSelfSignedCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("could not start TLS listener: %v", err)
	}
	defer listener.Close()
	go acceptAndDiscard(listener)

	t.Run("success with trusted CA", func(t *testing.T) {
		conn, err := utils.TLSConnectWithTimeout(listener.Addr().String(), &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			t.Fatalf("TLSConnectWithTimeout() error = %v", err)
		}
		defer conn.Close()
	})

	t.Run("untrusted certificate is rejected", func(t *testing.T) {
		_, err := utils.TLSConnectWithTimeout(listener.Addr().String(), &tls.Config{
			RootCAs:    x509.NewCertPool(),
			MinVersion: tls.VersionTLS12,
		})
		if err == nil {
			t.Error("expected a certificate verification error, got nil")
		}
	})
}

func acceptAndDiscard(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(io.Discard, c)
		}(conn)
	}
}

func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-utils"},
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

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}
