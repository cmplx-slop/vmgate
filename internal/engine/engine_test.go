package engine_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"vmgate/internal/config"
	"vmgate/internal/fixture"
)

// hostTCP starts a line-oriented TCP server on the host and returns the port it
// listens on. Every line the client sends comes back prefixed.
func hostTCP(t *testing.T, prefix string) uint16 {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("host listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					if _, err := fmt.Fprintf(c, "%s%s\n", prefix, sc.Text()); err != nil {
						return
					}
				}
				// A truncated line only stops this echo: the test's own
				// assertion is what notices when an answer never arrives.
			}(c)
		}
	}()

	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("host addr: %v", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("host port: %v", err)
	}
	return uint16(n)
}

func exchange(t *testing.T, conn net.Conn, send string) string {
	t.Helper()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, send+"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// TestGatewayTCPService is the [[service]] case: a guest connection to the
// connects to the gateway and lands on a socket the host opened.
func TestGatewayTCPService(t *testing.T) {
	hostPort := hostTCP(t, "host:")

	n := fixture.New(t, func(f *config.File) {
		f.Service = []config.Service{{GuestPort: 80, HostAddr: "127.0.0.1", HostPort: hostPort}}
	})
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, "10.0.2.2", 80)
	if err != nil {
		t.Fatalf("guest dial 10.0.2.2:80: %v", err)
	}
	defer conn.Close()

	if got, want := exchange(t, conn, "ping"), "host:ping"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// hostUDP starts a datagram echo server on the host and returns the port it
// listens on. Replies are prefixed so a test can tell an answer from its own
// target from one that came from somewhere else.
func hostUDP(t *testing.T, prefix string) uint16 {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("host udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteTo(append([]byte(prefix), buf[:n]...), from); err != nil {
				return
			}
		}
	}()

	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("host udp address: %v", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("host udp port: %v", err)
	}
	return uint16(n)
}

// A [[service]] aimed at an endpoint the operator named still goes out the host's
// own socket: the tunnel carries a guest's destinations, not the ones the
// configuration chose. It is also the path someone on the gateway's network would
// have to ride to push datagrams at a guest, so it is worth covering end to end.
func TestGatewayUDPService(t *testing.T) {
	hostPort := hostUDP(t, "host:")

	n := fixture.New(t, func(f *config.File) {
		f.Service = []config.Service{{
			GuestPort: 5300,
			HostAddr:  "127.0.0.1",
			HostPort:  hostPort,
			Proto:     "udp",
		}}
	})
	n.Configure()

	reply, err := n.Exchange([]byte("ping"), n.Cfg.GatewayIP, 5300, 20*time.Second)
	if err != nil {
		t.Fatalf("guest udp to %s:5300: %v", n.Cfg.GatewayIP, err)
	}
	if got := string(reply); got != "host:ping" {
		t.Fatalf("got %q, want %q", got, "host:ping")
	}
}

// TestDNSSyntheticHost checks the built-in resolver answers names configured
// in dns.map_hosts without leaving the process.
func TestDNSSyntheticHost(t *testing.T) {
	n := fixture.New(t, func(f *config.File) {
		f.DNS.MapHosts = []string{"host.local"}
	})
	n.Configure()

	msg := dnsQuery("host.local")
	reply, err := n.Exchange(msg, n.Cfg.DNSIP, 53, 10*time.Second)
	if err != nil {
		t.Fatalf("guest dns query: %v", err)
	}
	answers, ip := dnsAnswers(t, reply)
	if answers != 1 {
		t.Fatalf("answers = %d, want 1 (% x)", answers, reply)
	}
	if !ip.Equal(n.Cfg.GatewayIP) {
		t.Fatalf("answer = %v, want the gateway %v", ip, n.Cfg.GatewayIP)
	}
}
