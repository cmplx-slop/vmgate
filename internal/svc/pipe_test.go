package svc

import (
	"net"
	"testing"
	"time"
)

// The host socket a [[service]] relay uses is an ephemeral one, and anyone who
// can see it can write to it. Only the target's own datagrams may be handed to a
// guest: a relay that took a datagram from anywhere would let any host on the
// network put bytes into a guest's flow without the guest having asked.
func TestHostPipeIgnoresOtherSources(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	stranger, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stranger.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	to, err := net.ResolveUDPAddr("udp", target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	here, err := net.ResolveUDPAddr("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	p := hostPipe{pc: pc, to: to}

	// The stranger guesses the socket, and the target answers properly.
	if _, err := stranger.WriteTo([]byte("forged"), here); err != nil {
		t.Fatal(err)
	}
	if _, err := target.WriteTo([]byte("real"), here); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	n, err := p.Read(buf)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if got := string(buf[:n]); got != "real" {
		t.Fatalf("recv handed the guest %q, want only the target's own answer", got)
	}

	// Nothing else is waiting: the forged datagram was skipped, not queued for
	// later.
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	}
	if n, err := p.Read(buf); err == nil {
		t.Fatalf("recv later produced %q", buf[:n])
	}
}

// The pipe used for a host endpoint has to send to the target that was resolved
// when the path was opened, and Close has to give the socket back.
func TestHostPipeSendsToItsTarget(t *testing.T) {
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	to, err := net.ResolveUDPAddr("udp", target.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	p := hostPipe{pc: pc, to: to}

	if _, err := p.Write([]byte("ask")); err != nil {
		t.Fatalf("send: %v", err)
	}

	buf := make([]byte, 64)
	if err := target.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, from, err := target.ReadFrom(buf)
	if err != nil {
		t.Fatalf("target read: %v", err)
	}
	if got := string(buf[:n]); got != "ask" {
		t.Fatalf("target got %q", got)
	}
	// The datagram has to come from the socket the pipe owns: that is the
	// address a reply has to be sent to, and the one recv will accept.
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("from is %T", from)
	}
	here, err := net.ResolveUDPAddr("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if ua.Port != here.Port || !ua.IP.Equal(here.IP) {
		t.Fatalf("the datagram came from %v, want the pipe's own socket %v", ua, here)
	}

	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := p.Write([]byte("again")); err == nil {
		t.Fatal("a closed pipe still sends")
	}
}
