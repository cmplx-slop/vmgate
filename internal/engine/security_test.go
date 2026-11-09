package engine_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/engine"
	"github.com/cmplx-slop/vmgate/internal/fixture"
	"github.com/cmplx-slop/vmgate/internal/testutil"
)

// metadata is the address every guest that can reach the internet is pointed
// at in the wild: the cloud credential endpoint lives in link-local.
const metadata = "169.254.169.254"

// The guest chooses the destination of an on-demand relay, so a policy has to
// stand in front of it. These frames are written straight onto the link, which
// is what a hostile guest does, and they include addresses a well behaved guest
// stack would never send. The refusal is checked where it matters: no listener
// is ever created for a destination the policy will not carry, whatever the
// tunnel would have made of it.
func TestEgressRefusesReservedDestinations(t *testing.T) {
	for _, addr := range []string{
		metadata,          // cloud credentials
		"127.0.0.1",       // the host itself
		"0.0.0.0",         // "this host, this network"
		"100.64.0.1",      // carrier NAT and overlay space
		"224.0.0.251",     // multicast
		"255.255.255.255", // broadcast
		"169.254.1.1",     // the rest of link-local
	} {
		t.Run(addr, func(t *testing.T) {
			r := fixture.Link(t, nil)

			frame := ipFrame(net.ParseIP("10.0.2.15"), net.ParseIP(addr), 51000, 80, []byte("hello"))
			if err := r.Frames.WriteFrame(frame); err != nil {
				t.Fatalf("write frame: %v", err)
			}

			testutil.WaitFor(t, "the refusal to be counted", func() bool { return r.Eng.Stats().Denied >= 1 })
			if got := r.Eng.Stats().Relays; got != 0 {
				t.Fatalf("relays = %d: a refused destination must not get a listener", got)
			}
		})
	}
}

// A refused destination stays refused for the neighbours of the address that
// was named in allow_egress: lifting one address is not opening the range. The
// allowed address is one the tunnel really can carry, so the only thing between
// the guest and it is the policy.
func TestEgressAllowOpensOneAddress(t *testing.T) {
	n := fixture.New(t, func(f *config.File) {
		f.Gateway.AllowEgress = []string{metadata}
	})
	n.VPN.ServeUDP(metadata, 53, "echo:")
	n.Configure()

	reply, err := n.Exchange([]byte("whois"), net.ParseIP(metadata), 53, 20*time.Second)
	if err != nil {
		t.Fatalf("allowed address unreachable: %v", err)
	}
	if got := string(reply); got != "echo:whois" {
		t.Fatalf("got %q, want %q", got, "echo:whois")
	}

	// The rest of the range is still refused, and nothing is dialled for it.
	if _, err := n.Exchange([]byte("nope"), net.ParseIP("169.254.1.1"), 53, 5*time.Second); err == nil {
		t.Fatal("a neighbour of the allowed address got through")
	}
	if got := n.Eng.Stats().Denied; got == 0 {
		t.Error("the neighbour of an allowed address was not counted as refused")
	}
	if got := n.Eng.Stats().Relays; got != 1 {
		t.Errorf("relays = %d, want only the one for the allowed address", got)
	}
}

// An unused relay has to come back, or the relay table only ever grows and a
// guest can fill it and leave it full. It is taken away by the next relay that
// needs room rather than by a timer: the moment an idle relay matters is the
// moment another one is wanted.
func TestIdleRelayIsTakenAway(t *testing.T) {
	const (
		first  = "93.184.216.34"
		second = "93.184.216.35"
		idle   = 200 * time.Millisecond
	)

	n := fixture.New(t, nil, engine.WithRelayIdle(idle))
	n.VPN.ServeUDP(first, 53, "echo:")
	n.VPN.ServeUDP(second, 53, "echo:")
	n.Configure()

	got, err := n.Exchange([]byte("one"), net.ParseIP(first), 53, 20*time.Second)
	if err != nil {
		t.Fatalf("guest udp exchange: %v", err)
	}
	if string(got) != "echo:one" {
		t.Fatalf("got %q", got)
	}
	if n.Eng.Stats().Relays != 1 {
		t.Fatalf("relays = %d, want the one for %s", n.Eng.Stats().Relays, first)
	}

	// The idle window passes with the guest quiet. Nothing has asked for room,
	// so the relay is still there, and that is the deal: no goroutine is
	// watching the table.
	time.Sleep(3 * idle)
	if n.Eng.Stats().Relays != 1 {
		t.Fatal("an idle relay was taken away with nothing asking for its place")
	}

	// Asking for a second relay takes the idle one away first, and the flow
	// through the old address still works: a relay that was given back is
	// simply opened again.
	got, err = n.Exchange([]byte("two"), net.ParseIP(second), 53, 20*time.Second)
	if err != nil {
		t.Fatalf("guest udp exchange to the second address: %v", err)
	}
	if string(got) != "echo:two" {
		t.Fatalf("got %q, want %q", got, "echo:two")
	}
	if got := n.Eng.Stats().Relays; got != 1 {
		t.Errorf("relays = %d, want the idle one given back to make room", got)
	}

	got, err = n.Exchange([]byte("three"), net.ParseIP(first), 53, 20*time.Second)
	if err != nil {
		t.Fatalf("guest udp exchange after the old relay was given back: %v", err)
	}
	if string(got) != "echo:three" {
		t.Fatalf("got %q, want %q", got, "echo:three")
	}
}

// Relays belong to the guest that opened them.
func TestRelaysDoNotSurviveTheGuest(t *testing.T) {
	const fake = "93.184.216.34"

	r := fixture.Link(t, nil)

	frame := ipFrame(net.ParseIP("10.0.2.15"), net.ParseIP(fake), 51000, 53, []byte("ask"))
	if err := r.Frames.WriteFrame(frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	testutil.WaitFor(t, "a relay for the guest destination", func() bool { return r.Eng.Stats().Relays >= 1 })

	if err := r.Frames.Close(); err != nil {
		t.Logf("close link: %v", err)
	}
	testutil.WaitFor(t, "the relays to go with the guest", func() bool { return r.Eng.Stats().Relays == 0 })
}

// A guest can open as many translations as it likes; the gateway has to hold
// the line somewhere, because each one is a socket and two goroutines.
func TestTranslationCap(t *testing.T) {
	const fake = "93.184.216.34"

	n := fixture.New(t, nil, engine.WithMaxConns(2))
	n.VPN.ServeTCP(fake, 80, "capped:")
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var held []net.Conn
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()

	for i := range 2 {
		conn, err := n.DialTCP(ctx, fake, 80)
		if err != nil {
			t.Fatalf("guest dial %d: %v", i, err)
		}
		held = append(held, conn)
		if got, want := exchange(t, conn, fmt.Sprint(i)), fmt.Sprintf("capped:%d", i); got != want {
			t.Fatalf("connection %d: got %q, want %q", i, got, want)
		}
	}

	// The budget is full, so a third translation must not be served.
	third, err := n.DialTCP(ctx, fake, 80)
	if err == nil {
		defer third.Close()
		_, _ = third.Write([]byte("third\n"))
		_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 32)
		rd, rerr := third.Read(buf)
		if rd > 0 {
			t.Fatalf("a third translation was served: %q", buf[:rd])
		}
		if rerr == nil {
			t.Fatal("a third translation was served")
		}
	}
	if got := n.Eng.Stats().Conns; got > 2 {
		t.Fatalf("running translations = %d, want at most 2", got)
	}
}

// One relay is limited to a handful of far side sockets, but a guest that
// reaches many destinations multiplies relays by paths, and that product is what
// the host pays for in sockets. The guest also invents its own source addresses,
// so nothing above the gateway can tell it how many paths it may open: the
// budget has to be the gateway's own.
func TestDatagramPathBudget(t *testing.T) {
	const dest = "93.184.216.34"

	sources := []string{"10.0.2.15", "10.0.2.16", "10.0.2.17", "10.0.2.18"}
	send := func(r *fixture.Raw) {
		for _, src := range sources {
			fr := ipFrame(net.ParseIP(src), net.ParseIP(dest), 51000, 53, []byte("ask"))
			if err := r.Frames.WriteFrame(fr); err != nil {
				t.Fatalf("write frame: %v", err)
			}
		}
	}

	// First with room for all of them, which is what makes the cap below mean
	// something: the counter tracks paths that really opened.
	room := fixture.Link(t, nil, engine.WithMaxPathsTotal(8))
	send(room)
	testutil.WaitFor(t, "four datagram paths", func() bool { return room.Eng.Stats().Paths >= len(sources) })

	// Then with a budget of two, which the same traffic cannot exceed.
	r := fixture.Link(t, nil, engine.WithMaxPathsTotal(2))
	send(r)
	testutil.WaitFor(t, "two datagram paths", func() bool { return r.Eng.Stats().Paths >= 2 })

	// The other two datagrams have arrived by now or will shortly; whichever
	// way, they cannot turn into more paths than the gateway agreed to.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.Eng.Stats().Paths; got > 2 {
			t.Fatalf("datagram paths = %d, want at most 2", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := r.Eng.Stats().Paths; got != 2 {
		t.Errorf("datagram paths = %d, want 2", got)
	}
}

// A budget is only worth having if what was taken comes back. A relay that goes
// idle has to give up every path it was holding, or a gateway that served one
// busy afternoon would refuse the next guest for the rest of its life. What asks
// for the room is the next relay, so that is what the test reaches for.
func TestDatagramPathsAreGivenBack(t *testing.T) {
	const (
		first  = "93.184.216.34"
		second = "93.184.216.35"
		idle   = 200 * time.Millisecond
	)

	r := fixture.Link(t, nil, engine.WithRelayIdle(idle))

	for _, src := range []string{"10.0.2.15", "10.0.2.16", "10.0.2.17"} {
		fr := ipFrame(net.ParseIP(src), net.ParseIP(first), 51000, 53, []byte("ask"))
		if err := r.Frames.WriteFrame(fr); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}
	testutil.WaitFor(t, "three datagram paths", func() bool { return r.Eng.Stats().Paths >= 3 })

	// A gateway with nothing else to do keeps what it has: no goroutine is
	// watching the table for a relay that went quiet.
	time.Sleep(3 * idle)
	if got := r.Eng.Stats().Paths; got == 0 {
		t.Fatal("the paths came back with nothing asking for their place")
	}

	// Wanting another relay is asking. The idle one goes, and every path it was
	// holding goes with it.
	fr := ipFrame(net.ParseIP("10.0.2.15"), net.ParseIP(second), 51000, 53, []byte("ask"))
	if err := r.Frames.WriteFrame(fr); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	testutil.WaitFor(t, "the idle relay's paths back", func() bool { return r.Eng.Stats().Paths <= 1 })

	if got := r.Eng.Stats().Relays; got != 1 {
		t.Errorf("relays = %d, want the idle one replaced rather than added to", got)
	}
}

// A guest that vanishes in the middle of a connection must not leave the
// gateway holding the translation budget. If it did, the next guest, or the
// same one after a reboot, would find every TCP connection refused until the
// process was restarted, and a guest reboot is quite capable of doing this by
// accident.
func TestGuestRebootFreesTranslations(t *testing.T) {
	const fake = "93.184.216.34"

	n := fixture.New(t, nil, engine.WithMaxConns(2))
	n.VPN.ServeTCP(fake, 80, "held:")
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Two idle connections, which is the entire budget, and then the guest
	// goes away without closing them.
	for i := range 2 {
		conn, err := n.DialTCP(ctx, fake, 80)
		if err != nil {
			t.Fatalf("guest dial %d: %v", i, err)
		}
		defer conn.Close()
		if got, want := exchange(t, conn, fmt.Sprint(i)), fmt.Sprintf("held:%d", i); got != want {
			t.Fatalf("connection %d: got %q, want %q", i, got, want)
		}
	}
	if got := n.Eng.Stats().Conns; got != 2 {
		t.Fatalf("running translations = %d, want 2", got)
	}

	n.Reconnect()
	n.Configure()

	if got := n.Eng.Stats().Conns; got != 0 {
		t.Fatalf("translations survived the guest: %d still running", got)
	}
	if got := n.Eng.Stats().Relays; got != 0 {
		t.Fatalf("relays survived the guest: %d left", got)
	}

	conn, err := n.DialTCP(ctx, fake, 80)
	if err != nil {
		t.Fatalf("guest dial after the reboot: %v", err)
	}
	defer conn.Close()
	if got, want := exchange(t, conn, "again"), "held:again"; got != want {
		t.Fatalf("after the reboot: got %q, want %q", got, want)
	}
}
