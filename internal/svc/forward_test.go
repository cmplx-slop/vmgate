package svc

import (
	"io"
	"log/slog"
	"net"
	"testing"
)

// A [[forward]] sits on the host's own address because the operator asked for it
// there, so whoever can reach that address is asking the gateway for a guest
// connection: a goroutine, a host socket and a netstack endpoint each. The
// forwarder carries a fixed number of them and closes the rest, which is the
// difference between a forward that is busy and a process that is finished.
func TestForwarderStopsAtItsCeiling(t *testing.T) {
	f := NewForwarder(nil, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer f.Stop()

	// Fill the forwarder without a stack underneath it: the ceiling is decided
	// before the guest is dialled, so the refused connection below never needs
	// one.
	for i := range maxBridges {
		if !f.takeBridge() {
			t.Fatalf("connection %d was refused, want room for %d", i, maxBridges)
		}
	}

	if err := f.ForwardTCP("127.0.0.1:0", net.ParseIP("10.0.2.15"), 22); err != nil {
		t.Fatalf("forward: %v", err)
	}

	f.mu.Lock()
	addr := f.listeners[0].Addr()
	f.mu.Unlock()

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Error("a connection past the ceiling was carried instead of closed")
	}
	if got := f.BridgesRefused(); got != 1 {
		t.Errorf("refused = %d, want the one connection that was turned away", got)
	}
	if got := f.Bridges(); got != maxBridges {
		t.Errorf("carrying = %d, want the %d already in hand", got, maxBridges)
	}

	// Room comes back when a connection finishes, so the ceiling is a ceiling and
	// not a shutdown.
	f.dropBridge()
	if !f.takeBridge() {
		t.Error("room was not given back when a connection ended")
	}
}
