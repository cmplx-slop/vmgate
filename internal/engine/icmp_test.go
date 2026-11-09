package engine_test

import (
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/ethlink"
	"github.com/cmplx-slop/vmgate/internal/fixture"
)

// The guest's address and hardware address as the fixture's pool and guest stack
// use them, and the address this suite pings from.
var (
	guestIP   = net.ParseIP("10.0.2.15")
	guestAddr = net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44}
)

// tunOnly is the fixture's far tunnel address as a route the peer carries, for
// the test that wants a tunnel carrying one address and nothing else.
const tunOnly = "10.76.0.2/32"

// A ping is the first thing anyone tries when a guest cannot reach anything, so
// the four answers the gateway gives are pinned here: its own addresses are
// answered here, what the tunnel carries is relayed and answered by whoever is
// out there, and everything else is silent. The silence matters as much as the
// answer: the netstack has an echo responder that cannot be switched off, and on
// the guest interface it would answer a ping to any address at all, spoofed from
// the address that was pinged. Without the frame level handling these tests
// exercise, a guest would be told that a host it cannot reach does answer.

func TestEchoForTheGatewayIsAnswered(t *testing.T) {
	r := fixture.Link(t, nil)

	got := echoFrames(t, r)
	ping(t, r, r.Cfg.GatewayIP, 7, 3, []byte("here"))

	echo := wantEcho(t, got, 2*time.Second)
	if echo.Type != ethlink.TypeEchoReply {
		t.Errorf("type = %d, want an answer", echo.Type)
	}
	if !echo.SrcIP.Equal(r.Cfg.GatewayIP) || !echo.DstIP.Equal(guestIP) {
		t.Errorf("answer went %s to %s, want the gateway to the guest", echo.SrcIP, echo.DstIP)
	}
	if echo.Ident != 7 || echo.Seq != 3 {
		t.Errorf("ident/seq = %d/%d, want the pair the request used", echo.Ident, echo.Seq)
	}
	if string(echo.Payload) != "here" {
		t.Errorf("payload = %q, want it back unchanged", echo.Payload)
	}
	if echo.DstMAC.String() != guestAddr.String() {
		t.Errorf("answer went to %s, want the guest's own hardware address", echo.DstMAC)
	}

	// Exactly one answer: the stack's own responder would add a second, from the
	// same address, which a guest would see as a duplicated ping.
	noEcho(t, got, time.Second)

	if held := r.Eng.Stats().Link.Held; held == 0 {
		t.Error("the ping was not taken from the stack, so the stack answered it as well")
	}
	if answered := r.Eng.Stats().EchoAnswered; answered != 1 {
		t.Errorf("answered = %d, want 1", answered)
	}
}

// A destination the tunnel carries is answered by whoever is out there: the
// request leaves through WireGuard with the gateway's own identifier, and the
// answer that comes back is given to the guest with the identifier the guest
// used. The far end of the fixture's tunnel is a real netstack, so it answers
// for its own address the way any host would.
func TestEchoBeyondTheTunnelIsAnsweredThere(t *testing.T) {
	r := fixture.Link(t, nil)
	if !r.VPN.Handshake(5 * time.Second) {
		t.Fatal("the tunnel never came up")
	}

	got := echoFrames(t, r)
	ping(t, r, r.VPN.FarIP, 11, 4, []byte("away"))

	echo := wantEcho(t, got, 5*time.Second)
	if !echo.SrcIP.Equal(r.VPN.FarIP) {
		t.Errorf("answer came from %s, want the address that was pinged", echo.SrcIP)
	}
	if echo.Ident != 11 {
		t.Errorf("answer carries ident %d, want the guest's 11", echo.Ident)
	}
	if echo.Seq != 4 || string(echo.Payload) != "away" {
		t.Errorf("answer seq/payload = %d/%q, want them carried back", echo.Seq, echo.Payload)
	}
	if r.Eng.Stats().EchoRelayed != 1 {
		t.Errorf("relayed = %d, want 1", r.Eng.Stats().EchoRelayed)
	}
}

// A destination the peer does not carry gets nothing at all, and the reason is
// counted. This is the case the stack's own responder would get wrong: it would
// answer, because the guest interface is promiscuous and answers for whatever
// address a frame happens to name.
func TestEchoTheTunnelDoesNotCarryIsSilent(t *testing.T) {
	r := fixture.LinkAgainst(t, []string{tunOnly}, nil)

	got := echoFrames(t, r)
	ping(t, r, net.ParseIP("203.0.113.9"), 5, 1, []byte("nope"))

	noEcho(t, got, 3*time.Second)

	if denied := r.Eng.Stats().Denied; denied == 0 {
		t.Error("a ping to an unroutable address was not counted as denied")
	}
	if relayed := r.Eng.Stats().EchoRelayed; relayed != 0 {
		t.Errorf("relayed = %d, want 0", relayed)
	}
}

// A machine on the guest's own segment is not the gateway's to answer: it does
// not know whether that machine is up, and the tunnel would let whoever holds
// the peer's key claim to be it.
func TestEchoIntoTheGuestSegmentIsSilent(t *testing.T) {
	r := fixture.Link(t, nil)

	got := echoFrames(t, r)
	ping(t, r, net.ParseIP("10.0.2.99"), 5, 1, []byte("neighbour"))

	noEcho(t, got, 3*time.Second)

	if denied := r.Eng.Stats().Denied; denied == 0 {
		t.Error("a ping to the guest's own subnet was not counted as denied")
	}
}

// With gateway.internet off, a ping to somewhere beyond the link is dropped
// without a word, the same as a TCP or UDP attempt: the absence of an answer is
// the answer.
func TestEchoWithInternetOffIsSilent(t *testing.T) {
	r := fixture.Link(t, func(f *config.File) { f.Gateway.Internet = false })

	got := echoFrames(t, r)
	ping(t, r, net.ParseIP("93.184.216.34"), 5, 1, []byte("out"))

	noEcho(t, got, 2*time.Second)
	if relayed := r.Eng.Stats().EchoRelayed; relayed != 0 {
		t.Errorf("relayed = %d, want 0 with internet off", relayed)
	}

	// The gateway's own address still answers: that has nothing to do with the
	// tunnel.
	ping(t, r, r.Cfg.GatewayIP, 5, 2, []byte("here"))
	if echo := wantEcho(t, got, 2*time.Second); !echo.SrcIP.Equal(r.Cfg.GatewayIP) {
		t.Errorf("answer came from %s, want the gateway itself", echo.SrcIP)
	}
}

// echoFrames reads the link and hands over every frame that carries an echo,
// copied out of the buffer the frame stream reuses.
func echoFrames(t *testing.T, r *fixture.Raw) <-chan ethlink.Echo {
	t.Helper()

	out := make(chan ethlink.Echo, 32)
	go func() {
		for {
			fr, err := r.Frames.ReadFrame()
			if err != nil {
				return
			}
			echo, ok := ethlink.ParseEcho(fr)
			if !ok {
				continue
			}
			out <- echo
		}
	}()
	return out
}

// ping sends one echo request from the guest to dst, addressed to the gateway's
// hardware address as a guest's would be.
func ping(t *testing.T, r *fixture.Raw, dst net.IP, ident, seq uint16, payload []byte) {
	t.Helper()

	req := ethlink.EchoRequest(guestAddr, r.Cfg.MAC, guestIP, dst, ident, seq, payload)
	if err := r.Frames.WriteFrame(ethlink.EchoFrame(req)); err != nil {
		t.Fatalf("write ping: %v", err)
	}
}

// wantEcho waits for the next echo to come back to the guest.
func wantEcho(t *testing.T, from <-chan ethlink.Echo, within time.Duration) ethlink.Echo {
	t.Helper()

	select {
	case echo := <-from:
		return echo
	case <-time.After(within):
		t.Fatal("no echo came back")
		return ethlink.Echo{}
	}
}

// noEcho insists that nothing comes back for a while. Frames that are not
// echoes never reach the channel, so there is nothing here to skip over.
func noEcho(t *testing.T, from <-chan ethlink.Echo, within time.Duration) {
	t.Helper()

	select {
	case echo := <-from:
		t.Fatalf("an echo came back from %s to %s", echo.SrcIP, echo.DstIP)
	case <-time.After(within):
	}
}

// The gateway claims the guest segment's broadcast address, so that a guest
// sending there is not treated as a destination to relay. That claim must not
// turn into an answer: a guest that gets a reply from 10.0.2.255 learns the
// gateway's hardware address under a broadcast address and keeps looking for a
// machine that is not there.
func TestEchoForTheSegmentBroadcastIsNotAnswered(t *testing.T) {
	r := fixture.Link(t, nil)

	got := echoFrames(t, r)
	ping(t, r, net.ParseIP("10.0.2.255"), 9, 1, []byte("shout"))

	noEcho(t, got, 2*time.Second)

	if answered := r.Eng.Stats().EchoAnswered; answered != 0 {
		t.Errorf("answered = %d, want 0: a broadcast address is not a machine", answered)
	}
	if held := r.Eng.Stats().Link.Held; held == 0 {
		t.Error("the ping was left to the stack, which answers from the address pinged")
	}
}
