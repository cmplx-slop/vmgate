package svc

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/ethlink"
)

// guestPing is one guest's echo request, built the way the link would hand it
// over: the guest's MAC and address in front, the destination asked for behind.
func guestPing(dst net.IP, ident, seq uint16, payload []byte) []byte {
	req := ethlink.EchoRequest(
		net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44},
		net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01},
		net.ParseIP("10.0.2.15"), dst, ident, seq, payload,
	)
	return ethlink.EchoFrame(req)
}

// guestPingFrom is the same request from a different machine: a second guest on
// the segment has its own address and its own hardware address, and may well
// have picked the same identifier.
func guestPingFrom(srcMAC net.HardwareAddr, srcIP, dst net.IP, ident, seq uint16, payload []byte) []byte {
	req := ethlink.EchoRequest(
		srcMAC,
		net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01},
		srcIP, dst, ident, seq, payload,
	)
	return ethlink.EchoFrame(req)
}

// framesWritten stands where the link stands on the way out: it records the
// frames the gateway asked for, so a test can read its own answers back.
type framesWritten struct {
	mu   sync.Mutex
	list [][]byte
	cond *sync.Cond
}

func newFramesWritten() *framesWritten {
	f := &framesWritten{}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *framesWritten) WriteFrame(fr []byte) error {
	f.mu.Lock()
	f.list = append(f.list, append([]byte(nil), fr...))
	f.cond.Broadcast()
	f.mu.Unlock()
	return nil
}

func (f *framesWritten) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.list)
}

// nthEcho waits for at least n+1 frames and reads the echo out of the n-th one,
// which is what a test needs when the order the answers went out in is the
// thing being checked.
func (f *framesWritten) nthEcho(t *testing.T, n int, within time.Duration) ethlink.Echo {
	t.Helper()

	done := make(chan ethlink.Echo, 1)
	go func() {
		f.mu.Lock()
		for len(f.list) <= n {
			f.cond.Wait()
		}
		fr := f.list[n]
		f.mu.Unlock()

		echo, ok := ethlink.ParseEcho(fr)
		if !ok {
			t.Errorf("frame %d written back is not an icmp echo: %d bytes", n, len(fr))
			return
		}
		done <- echo
	}()

	select {
	case echo := <-done:
		return echo
	case <-time.After(within):
		t.Fatalf("no second answer arrived within %v", within)
		return ethlink.Echo{}
	}
}

// lastEcho waits for a frame to have been written and reads the echo out of it.
func (f *framesWritten) lastEcho(t *testing.T, within time.Duration) ethlink.Echo {
	t.Helper()

	done := make(chan ethlink.Echo, 1)
	go func() {
		f.mu.Lock()
		for len(f.list) == 0 {
			f.cond.Wait()
		}
		fr := f.list[len(f.list)-1]
		f.mu.Unlock()
		echo, ok := ethlink.ParseEcho(fr)
		if !ok {
			t.Errorf("the frame written back is not an icmp echo: %d bytes", len(fr))
			return
		}
		done <- echo
	}()

	select {
	case echo := <-done:
		return echo
	case <-time.After(within):
		t.Fatalf("no frame was written within %v", within)
		return ethlink.Echo{}
	}
}

// echoManager is a manager with everything an ICMP answer needs and nothing else:
// the addresses it owns, the guest's subnet, an egress seam, and a frame writer
// standing in for the link. There is no netstack, because answering an echo does
// not use one.
func echoManager(t *testing.T, tunnel Egress) (*Manager, *framesWritten) {
	t.Helper()

	policy, err := config.ParseEgress(nil, nil)
	if err != nil {
		t.Fatalf("egress policy: %v", err)
	}
	frames := newFramesWritten()
	m := NewManager(nil, 1, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Limits{}, frames)
	t.Cleanup(m.Stop)
	m.EnableInternet(true)
	m.Own(net.ParseIP("10.0.2.2"))
	m.SetGuestSubnet(&net.IPNet{IP: net.ParseIP("10.0.2.0"), Mask: net.CIDRMask(24, 32)})
	m.SetEgressPolicy(policy)
	if tunnel != nil {
		m.SetEgress(tunnel)
	}
	return m, frames
}

// The gateway's own address is answered here, at once, and the answer is the
// request turned around: same identifier, sequence and payload, addresses
// swapped, and the guest's own MAC in front of it.
func TestEchoForOurOwnAddressIsAnswered(t *testing.T) {
	m, frames := echoManager(t, &fakeEgress{})

	if m.Inspect(guestPing(net.ParseIP("10.0.2.2"), 7, 3, []byte("hello"))) {
		t.Fatal("an echo frame was passed on to the stack, which would answer it a second time")
	}

	got := frames.lastEcho(t, 2*time.Second)
	if got.Type != ethlink.TypeEchoReply {
		t.Errorf("type = %d, want an echo answer", got.Type)
	}
	if !got.SrcIP.Equal(net.ParseIP("10.0.2.2")) || !got.DstIP.Equal(net.ParseIP("10.0.2.15")) {
		t.Errorf("answer came from %s to %s, want 10.0.2.2 to 10.0.2.15", got.SrcIP, got.DstIP)
	}
	if got.Ident != 7 || got.Seq != 3 {
		t.Errorf("ident/seq = %d/%d, want 7/3", got.Ident, got.Seq)
	}
	if string(got.Payload) != "hello" {
		t.Errorf("payload = %q, want it back unchanged", got.Payload)
	}
	if got.DstMAC.String() != "52:54:11:22:33:44" {
		t.Errorf("answer went to %s, the guest's own MAC", got.DstMAC)
	}
	if m.EchoAnswered() != 1 || m.EchoRelayed() != 0 {
		t.Errorf("answered/relayed = %d/%d, want 1/0", m.EchoAnswered(), m.EchoRelayed())
	}
}

// The dial itself is the destination policy: an address outside the peer's
// AllowedIPs has no route, and the guest gets nothing rather than an answer
// from this process.
func TestEchoWithoutARouteIsRefused(t *testing.T) {
	tunnel := &fakeEgress{echoErr: errors.New("no route through the tunnel")}
	m, frames := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("198.51.100.7"), 4, 1, []byte("x")))

	if frames.count() != 0 {
		t.Errorf("%d frames were written for a destination the tunnel does not carry", frames.count())
	}
	if m.Denied() == 0 {
		t.Error("the refusal was not counted")
	}
	if m.EchoRelayed() != 0 {
		t.Errorf("relayed = %d, want 0", m.EchoRelayed())
	}
}

// A destination on the guest's own segment is not the gateway's to answer, no
// matter what the tunnel would have carried.
func TestEchoInTheGuestSegmentIsRefused(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, frames := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("10.0.2.99"), 4, 1, []byte("neighbour")))

	if frames.count() != 0 {
		t.Errorf("%d frames were written for a machine on the guest's own LAN", frames.count())
	}
	if m.Denied() == 0 {
		t.Error("the refusal was not counted")
	}
	if tunnel.echoDials != 0 {
		t.Errorf("the tunnel was dialled %d times for a guest address", tunnel.echoDials)
	}
}

// A destination the egress policy names is refused before anything is dialled,
// the same rule the TCP and UDP relays follow.
func TestEchoInADeniedRangeIsRefused(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, frames := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("169.254.169.254"), 4, 1, []byte("metadata")))

	if frames.count() != 0 {
		t.Errorf("%d frames were written for a refused destination", frames.count())
	}
	if m.Denied() == 0 {
		t.Error("the refusal was not counted")
	}
	if tunnel.echoDials != 0 {
		t.Errorf("the tunnel was dialled %d times for a refused address", tunnel.echoDials)
	}
}

// Without a way back out, an echo is dropped rather than left to the stack:
// that is the whole reason the gateway takes these frames in the first place,
// so the fallback must not be the thing it was meant to avoid.
func TestEchoWithoutALinkIsDropped(t *testing.T) {
	m := NewManager(nil, 1, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Limits{}, nil)
	defer m.Stop()
	m.EnableInternet(true)
	m.Own(net.ParseIP("10.0.2.2"))
	m.SetEgress(&fakeEgress{})

	if m.Inspect(guestPing(net.ParseIP("10.0.2.2"), 1, 1, nil)) {
		t.Error("the frame was left to the stack, which answers with a spoofed source")
	}
	if m.EchoAnswered() != 0 || m.Denied() != 0 {
		t.Errorf("answered/denied = %d/%d, want 0/0 with nothing to write to", m.EchoAnswered(), m.Denied())
	}
}

// An answer the guest is sending, to a ping somebody else asked for, has no
// translation to carry it and is left where it is.
func TestEchoAnswerFromTheGuestIsIgnored(t *testing.T) {
	m, frames := echoManager(t, &fakeEgress{})

	req := ethlink.EchoRequest(
		net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44},
		net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01},
		net.ParseIP("10.0.2.15"), net.ParseIP("10.76.0.2"), 9, 1, nil,
	)
	req.Type = ethlink.TypeEchoReply
	if m.Inspect(ethlink.EchoFrame(req)) {
		t.Error("the stack was handed an echo frame")
	}
	if frames.count() != 0 {
		t.Errorf("%d frames came back for an answer the guest sent", frames.count())
	}
}

// The gateway does not claim the segment's broadcast address any more, and this
// checks that the ICMP rule does not depend on that: even an address the manager
// has been told it owns is not one to answer a ping out of. A guest that gets a
// reply from 10.0.2.255 learns this process's hardware address under a broadcast
// address and keeps looking for a machine there.
func TestEchoForTheSegmentBroadcastIsRefused(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, frames := echoManager(t, tunnel)
	m.Own(net.ParseIP("10.0.2.255"))

	if m.Inspect(guestPing(net.ParseIP("10.0.2.255"), 9, 1, []byte("shout"))) {
		t.Fatal("the frame was left to the stack, which answers from the address pinged")
	}
	if frames.count() != 0 {
		t.Errorf("%d frames came back for a broadcast address", frames.count())
	}
	if m.EchoAnswered() != 0 {
		t.Errorf("answered = %d, want 0: a broadcast address is not a machine", m.EchoAnswered())
	}
	if m.Denied() == 0 {
		t.Error("the refusal was not counted")
	}
	if tunnel.echoDials != 0 {
		t.Errorf("the tunnel was dialled %d times for a broadcast address", tunnel.echoDials)
	}
}

// A ping split into fragments is not a way past the policy. ParseEcho cannot read
// a fragment, and if the frame were left to the netstack the stack would put the
// datagram back together and its echo responder would answer for the address the
// request named, whatever the gateway's rules say about it. So a fragment of an
// ICMP datagram is refused at the frame level, and counted.
func TestFragmentedEchoIsRefused(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, frames := echoManager(t, tunnel)

	ping := guestPing(net.ParseIP("203.0.113.9"), 4, 1, []byte("split"))
	for _, fr := range []*[]byte{&ping} {
		(*fr)[14+6] = 0x20 // more fragments, offset 0
	}

	if m.Inspect(ping) {
		t.Fatal("a fragment of a ping was handed to the stack, which reassembles and answers it")
	}
	if frames.count() != 0 {
		t.Errorf("%d frames came back for a fragmented ping", frames.count())
	}
	if m.EchoAnswered() != 0 || m.EchoRelayed() != 0 {
		t.Errorf("answered/relayed = %d/%d, want 0/0", m.EchoAnswered(), m.EchoRelayed())
	}
	if m.Denied() == 0 {
		t.Error("the refusal was not counted")
	}
	if tunnel.echoDials != 0 {
		t.Errorf("the tunnel was dialled %d times for a fragment", tunnel.echoDials)
	}
}

// A request whose checksums do not add up is refused, not answered. The gateway
// is the receiver for echo frames, because it takes them away from the stack, and
// answering a corrupt request is worse than dropping it: the guest gets a reply to
// a ping it never really sent, and a destination beyond the tunnel would get the
// guest's payload put on the wire unexamined.
func TestEchoWithABrokenChecksumIsRefused(t *testing.T) {
	tunnel := &fakeEgress{echoPath: newFakeEchoPath()}
	m, frames := echoManager(t, tunnel)

	for _, dst := range []string{"10.0.2.2", "93.184.216.34"} {
		fr := guestPing(net.ParseIP(dst), 11, 5, []byte("junk"))
		fr[len(fr)-1] ^= 0xff // one bit of the payload, and with it the sum

		if m.Inspect(fr) {
			t.Errorf("%s: a corrupt echo frame reached the stack, which answers it "+
				"without looking at the sum", dst)
		}
	}

	if frames.count() != 0 {
		t.Errorf("%d frames came back for a request that does not add up", frames.count())
	}
	if m.EchoAnswered() != 0 {
		t.Errorf("answered = %d, want nothing counted for a corrupt request", m.EchoAnswered())
	}
	if tunnel.echoDials != 0 {
		t.Errorf("the tunnel was dialled %d times for a corrupt request", tunnel.echoDials)
	}
	if m.Denied() != 2 {
		t.Errorf("denied = %d, want both corrupt requests counted", m.Denied())
	}
}
