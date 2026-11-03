package engine_test

import (
	"bytes"
	"context"
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

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/config"
	"vmgate/internal/fixture"
	"vmgate/internal/nsnet"
)

// A TLS handshake is the first thing a guest normally does that puts a full
// packet of data in each direction: the client hello is over a kilobyte, and
// the certificate beyond the server hello runs to several more. It is also the
// traffic whose failure an operator hears about in the language of the client
// rather than the gateway's ("unexpected eof while reading"), so the transit
// path is checked with a real handshake rather than with the one line exchanges
// the relay tests use.
//
// farNIC is the interface number the fixture's far side puts its tunnel on.
const farNIC = tcpip.NICID(1)

// serveTLS puts a TLS server beyond the tunnel for ip:port. The certificate is
// deliberately large, so the flight the gateway has to carry is a few packets
// rather than one, and the server echoes whatever the client sends, so the same
// connection can carry a bulk transfer in both directions.
func serveTLS(t *testing.T, n *fixture.Net, ip string, port uint16) {
	t.Helper()

	n.VPN.AddAddress(ip)
	l, err := gonet.ListenTCP(n.VPN.Stack(), nsnet.Full(farNIC, net.ParseIP(ip), port), header.IPv4ProtocolNumber)
	if err != nil {
		t.Fatalf("far listen tls %s:%d: %v", ip, port, err)
	}
	t.Cleanup(func() { _ = l.Close() })

	cert := bigCertificate(t)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tlsConn.HandshakeContext(context.Background()); err != nil {
					t.Logf("far tls handshake: %v", err)
					return
				}
				_, _ = io.Copy(tlsConn, tlsConn)
			}(conn)
		}
	}()
}

// bigCertificate makes a self-signed certificate with a long subject, so that a
// handshake carries something worth fragmenting.
func bigCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "transit.example.com",
			Organization: []string{string(make([]byte, 1024))},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		DNSNames:  []string{"transit.example.com", "www.transit.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestTLSTransit asks the gateway to carry a handshake and then a transfer
// larger than any single packet, in both directions. The sizes are the ones a
// real client hello and certificate chain produce, and the bulk case is where a
// relay that stops short would show it: everything below one packet per
// direction passes even when the path cannot carry an assembled stream.
func TestTLSTransit(t *testing.T) {
	const (
		fake = "93.184.216.34"
		port = 443
	)

	n := fixture.New(t, nil)
	serveTLS(t, n, fake, port)
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, fake, port)
	if err != nil {
		t.Fatalf("guest dial %s:%d: %v", fake, port, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "transit.example.com"})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("guest tls handshake through the gateway: %v", err)
	}

	// One request, and then enough bytes both ways to fill a dozen packets. The
	// server echoes, so what comes back has to match byte for byte: a relay that
	// dropped or reordered a segment would show up here rather than as a slower
	// connection.
	body := make([]byte, 24*1024)
	for i := range body {
		body[i] = byte(i*31 + i/251)
	}
	if _, err := tlsConn.Write(body); err != nil {
		t.Fatalf("tls write of %d bytes: %v", len(body), err)
	}
	got := make([]byte, len(body))
	if _, err := io.ReadFull(tlsConn, got); err != nil {
		t.Fatalf("tls read of %d bytes: %v", len(body), err)
	}
	for i := range got {
		if got[i] != body[i] {
			t.Fatalf("byte %d of %d came back as %d, want %d", i, len(body), got[i], body[i])
		}
	}

	if s := n.Eng.Stats(); s.Denied != 0 {
		t.Errorf("a destination the tunnel carries was refused %d times", s.Denied)
	}
}

// TestGuestPacketLargerThanTheTunnelCrosses: the gateway lowers its own link
// MTU to the tunnel's and hands the number out with DHCP, but a guest is free
// to ignore it and size its packets for 1500. The relay ends the guest's TCP and
// starts its own on the tunnel side, so the guest's oversized packet is
// re-segmented rather than dropped, and a guest that never read the option
// still reaches the internet.
func TestGuestPacketLargerThanTheTunnelCrosses(t *testing.T) {
	const fake = "93.184.216.34"

	// The guest's stack sizes its packets for what its configuration says, not
	// for what the gateway would have preferred: 1500 against a 1420 tunnel.
	n := fixture.New(t, func(f *config.File) { f.Network.MTU = 1500 })
	serveTLS(t, n, fake, 443)
	n.Configure()

	if got := n.VPN.MTU; got >= 1500 {
		t.Fatalf("the fixture's tunnel is %d bytes: this test wants the guest's packets larger than it", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, fake, 443)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(25 * time.Second))

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "transit.example.com"})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("tls handshake from a guest using 1500 byte packets: %v", err)
	}

	// Enough plaintext that the record layer fills the guest's own packets: the
	// gateway sees 1500 byte packets arrive and has to send something smaller on.
	body := bytes.Repeat([]byte("abcdefghij"), 200) // 2000 bytes
	if _, err := tlsConn.Write(body); err != nil {
		t.Fatalf("tls write: %v", err)
	}
	got := make([]byte, len(body))
	if _, err := io.ReadFull(tlsConn, got); err != nil {
		t.Fatalf("tls read: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("a %d byte exchange with a guest at 1500 came back differently", len(body))
	}
}
