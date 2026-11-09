package engine_test

import (
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/fixture"
)

// The frame transport will carry a frame of up to 65535 bytes, the stack
// reassembles whatever the guest fragments, and the netstack panics if a
// reader's buffer is smaller than the packet handed to it. Every reader in the
// gateway uses a buffer of a couple of kilobytes, which used to mean that one
// oversized datagram from a guest, or one oversized answer from beyond the
// tunnel, ended the process: a guest could switch the gateway off for every
// other guest with a single frame. The gateway has to truncate instead.

func TestOversizedDatagramsDoNotEndTheGateway(t *testing.T) {
	r := fixture.Link(t, nil)

	// Sizes past what the DNS service, the DHCP server and a UDP relay read,
	// aimed at each of the gateway's own ports.
	for _, size := range []int{3000, 5000} {
		targets := []struct {
			dst  net.IP
			port uint16
		}{
			{r.Cfg.DNSIP, 53},
			{r.Cfg.GatewayIP, 67},
			{r.Cfg.GatewayIP, 9},
		}
		for _, tgt := range targets {
			fr := ipFrame(guestIP, tgt.dst, 40000, tgt.port, make([]byte, size))
			if err := r.Frames.WriteFrame(fr); err != nil {
				t.Fatalf("write %d bytes to %s:%d: %v", size, tgt.dst, tgt.port, err)
			}
		}
	}

	// Six oversized datagrams later the gateway is still itself: the cheapest
	// proof is the path that answers a ping, which goes through the same frame
	// handling and the same manager.
	got := echoFrames(t, r)
	ping(t, r, r.Cfg.GatewayIP, 3, 1, []byte("still here"))

	echo := wantEcho(t, got, 5*time.Second)
	if !echo.SrcIP.Equal(r.Cfg.GatewayIP) || !echo.DstIP.Equal(guestIP) {
		t.Errorf("answer went %s to %s, want the gateway to the guest", echo.SrcIP, echo.DstIP)
	}
	if string(echo.Payload) != "still here" {
		t.Errorf("payload = %q, want it back unchanged", echo.Payload)
	}
}

// An oversized ping is the same problem on the way back: the gateway relays the
// request through the tunnel, whoever is out there answers with as much data as
// was asked for, and the answer is larger than the buffer the relay reads into.
// The guest gets a truncated answer; the process stays up.
func TestOversizedPingThroughTheTunnelIsTruncated(t *testing.T) {
	r := fixture.Link(t, nil)
	if !r.VPN.Handshake(5 * time.Second) {
		t.Fatal("the tunnel never came up")
	}

	got := echoFrames(t, r)
	ping(t, r, r.VPN.FarIP, 7, 1, make([]byte, 3000))

	echo := wantEcho(t, got, 5*time.Second)
	if echo.Ident != 7 {
		t.Errorf("answer carries ident %d, want the guest's 7", echo.Ident)
	}
	if len(echo.Payload) == 0 {
		t.Fatal("the answer came back with no payload at all")
	}
	if len(echo.Payload) > 3000 {
		t.Errorf("answer payload is %d bytes, more than was asked for", len(echo.Payload))
	}

	// The relay is still usable afterwards: the slot was not left half-open by
	// the truncated read.
	ping(t, r, r.VPN.FarIP, 7, 2, []byte("again"))
	again := wantEcho(t, got, 5*time.Second)
	if again.Seq != 2 || string(again.Payload) != "again" {
		t.Errorf("second answer seq/payload = %d/%q, want 2/again", again.Seq, again.Payload)
	}
}
