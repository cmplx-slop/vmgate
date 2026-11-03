package svc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// fakeEgress stands where the VPN tunnel stands. That is only possible because
// the seam says nothing about gVisor or wireguard: a test can hand a relay a
// pretend path out and watch what goes along it, which is the only way the
// branch that decides "everything the guest chose leaves through the tunnel"
// gets looked at without a stack, a tunnel and a pretend guest around it.
type fakeEgress struct {
	udpAsked string
	path     Datagram
	err      error

	echoAsked string
	echoPath  EchoPath
	echoPaths []EchoPath // handed out in order, one per dial
	echoErr   error
	echoDials int
}

func (f *fakeEgress) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("fake: no dial in this test")
}

func (f *fakeEgress) DialUDP(address string) (Datagram, error) {
	f.udpAsked = address
	return f.path, f.err
}

func (f *fakeEgress) DialEcho(address string) (EchoPath, error) {
	f.echoAsked = address
	f.echoDials++
	if len(f.echoPaths) > 0 {
		p := f.echoPaths[0]
		f.echoPaths = f.echoPaths[1:]
		return p, f.echoErr
	}
	return f.echoPath, f.echoErr
}

func quietManager() *Manager {
	return NewManager(nil, 1, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Limits{}, nil)
}

// A destination the guest chose is dialled through the egress seam and nothing
// else, and with no tunnel the answer is a refusal rather than a host socket:
// that is the difference between a gateway behind a VPN and one that quietly
// leaks the guest somewhere else.
func TestUDPEgressLeavesThroughTheTunnel(t *testing.T) {
	m := quietManager()
	defer m.Stop()

	const dest = "93.184.216.34:53"

	if _, err := m.openUDP(dest, false); !errors.Is(err, errNoTunnel) {
		t.Fatalf("openUDP with no tunnel = %v, want the refusal", err)
	}

	// A real loopback pair rather than net.Pipe: the relay writes and then
	// reads, and an unbuffered pipe would deadlock the test rather than tell me
	// anything about the code. A connected UDP socket is also closer to the
	// tunnel, which is connected in the same way.
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srv.Close()

	conn, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	if err := srv.SetReadDeadline(deadline); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	asked := &fakeEgress{path: conn}
	m.SetEgress(asked)

	p, err := m.openUDP(dest, false)
	if err != nil {
		t.Fatalf("openUDP: %v", err)
	}
	if asked.udpAsked != dest {
		t.Errorf("the tunnel was asked for %q, want %q", asked.udpAsked, dest)
	}

	// What the relay writes leaves along the tunnel, and what comes back along
	// it is what the relay reads.
	if _, err := p.Write([]byte("ask")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	n, from, err := srv.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the tunnel never saw the datagram: %v", err)
	}
	if got := string(buf[:n]); got != "ask" {
		t.Errorf("the tunnel received %q, want %q", got, "ask")
	}

	if _, err := srv.WriteTo([]byte("answer"), from); err != nil {
		t.Fatalf("answer: %v", err)
	}
	if n, err = p.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != "answer" {
		t.Errorf("the relay read %q, want %q", got, "answer")
	}

	if err := p.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

// A tunnel that refuses a destination has to say so, so that the relay counts it
// as refused instead of reaching something the peer's AllowedIPs never named.
func TestUDPEgressRefusalTravelsBack(t *testing.T) {
	m := quietManager()
	defer m.Stop()

	m.SetEgress(&fakeEgress{err: errors.New("no route")})

	if _, err := m.openUDP("198.51.100.7:80", false); err == nil {
		t.Fatal("a tunnel that refused the destination was treated as though it had carried it")
	}
}
