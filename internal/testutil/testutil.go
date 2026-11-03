// Package testutil is the plumbing the gateway's tests share: a wait for
// something asynchronous, a spare port, a hardware address written the way a
// reader expects.
//
// It imports nothing else from this module on purpose. The harness in
// internal/fixture sits at the top of the import graph, so the tests of a
// package it drives cannot use it without a cycle; these helpers can be used
// by any package, from dhcp at the bottom to engine at the top.
//
// What is deliberately not here is packet building. Two tests that each write
// their own ethernet frame are two implementations of the same wire format, and
// that independence is what caught the transposed DHCP cookie: a shared
// encoder would have been wrong in the same way twice.
package testutil

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// MAC parses a hardware address or fails the test.
func MAC(t *testing.T, s string) []byte {
	t.Helper()

	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatalf("bad mac %q: %v", s, err)
	}
	return mac
}

// FreePort asks the host for a port nobody is using, so a test can name it to
// the gateway without winning a race with whatever else is on the machine. The
// port is held open by the returned listener: a test that only needs the number
// closes it, and the small window that follows is one every test of this kind
// accepts.
func FreePort(t *testing.T, network string) uint16 {
	t.Helper()

	switch network {
	case "udp":
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free %s port: %v", network, err)
		}
		defer c.Close()
		return portOf(t, c.LocalAddr().String())
	default:
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free %s port: %v", network, err)
		}
		defer l.Close()
		return portOf(t, l.Addr().String())
	}
}

func portOf(t *testing.T, addr string) uint16 {
	t.Helper()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("free port %q: %v", port, err)
	}
	return uint16(n)
}

// Within polls cond until it holds or the wait runs out, and reports which
// happened. It is for a test that wants to keep going after a failed wait, so
// that one run says everything that is wrong rather than stopping at the first
// thing. A test that cannot meaningfully continue wants WaitFor.
func Within(wait time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(wait)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// WaitFor is Within with the patience of a test that cannot go on without the
// condition, and it names what it was waiting for when it gives up.
func WaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	if !Within(5*time.Second, cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}
