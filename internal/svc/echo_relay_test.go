package svc

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/ethlink"
	"github.com/cmplx-slop/vmgate/internal/testutil"
)

// A destination the tunnel carries is dialled through the egress seam, and the
// answer comes back with the guest's identifier rather than the one the tunnel
// socket was given.
func TestEchoBeyondTheTunnelIsRelayed(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, frames := echoManager(t, tunnel)

	if m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 11, 5, []byte("away"))) {
		t.Fatal("an echo frame reached the stack")
	}
	if tunnel.echoAsked != "93.184.216.34" {
		t.Errorf("tunnel was asked for %q, want 93.184.216.34", tunnel.echoAsked)
	}
	if seq, payload := path.sent(); seq != 5 || string(payload) != "away" {
		t.Errorf("sent seq/payload = %d/%q, want 5/away", seq, payload)
	}

	// The far side answers with the sequence number of the request it was sent;
	// the guest has to see its own identifier back.
	path.answers <- answer{seq: 5, payload: []byte("away")}
	got := frames.lastEcho(t, 2*time.Second)
	if got.Ident != 11 {
		t.Errorf("answer carries ident %d, want the guest's 11", got.Ident)
	}
	if !got.SrcIP.Equal(net.ParseIP("93.184.216.34")) {
		t.Errorf("answer came from %s, want the address that was pinged", got.SrcIP)
	}
	if m.EchoRelayed() != 1 {
		t.Errorf("relayed = %d, want 1", m.EchoRelayed())
	}

	// A second ping from the same conversation reuses the one path out: one
	// guest identifier is one socket through the tunnel.
	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 11, 6, []byte("again")))
	if seq, payload := path.sent(); seq != 6 || string(payload) != "again" {
		t.Errorf("second send seq/payload = %d/%q, want 6/again", seq, payload)
	}
	if tunnel.echoDials != 1 {
		t.Errorf("the tunnel was dialled %d times for one conversation, want 1", tunnel.echoDials)
	}
}

// A request the path will not take has not been relayed. The counter is read as
// "how many pings left this process", so an attempt that failed on the way out
// must not answer it: that is how a stats line ends up claiming a guest reached
// a host that was never contacted.
func TestEchoIsCountedRelayedOnlyWhenItLeft(t *testing.T) {
	tunnel := &fakeEgress{echoPath: deadEchoPath{}}
	m, frames := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 12, 1, []byte("gone")))

	if frames.count() != 0 {
		t.Errorf("%d frames came back for a request that never left", frames.count())
	}
	if m.EchoRelayed() != 0 {
		t.Errorf("relayed = %d, want 0: nothing reached the tunnel", m.EchoRelayed())
	}
}

// Two guests picking the same identifier is the normal case, not a clever one:
// Linux's ping derives it from the process. So the guest that asked is part of
// what identifies a path out of the gateway. Leave it out and one path serves
// both: the second guest's ping is carried by the first guest's path, and its
// answer is written back to the first guest's address and hardware address,
// which is both a channel between two guests and a ping that never arrives.
func TestTwoGuestsSharingAnIdentifierGetTheirOwnAnswers(t *testing.T) {
	first, second := newFakeEchoPath(), newFakeEchoPath()
	tunnel := &fakeEgress{echoPaths: []EchoPath{first, second}}
	m, frames := echoManager(t, tunnel)

	const dest = "93.184.216.34"
	m.Inspect(guestPing(net.ParseIP(dest), 31, 1, []byte("one")))
	m.Inspect(guestPingFrom(
		net.HardwareAddr{0x52, 0x54, 0x99, 0x88, 0x77, 0x66},
		net.ParseIP("10.0.2.99"), net.ParseIP(dest), 31, 1, []byte("two")))

	if tunnel.echoDials != 2 {
		t.Fatalf("the tunnel was dialled %d times, want one path per guest", tunnel.echoDials)
	}
	if m.Relays() != 2 {
		t.Errorf("relays = %d, want two", m.Relays())
	}

	// Each guest has to get its own address and hardware address back. Which
	// answer leaves first is up to the two relay goroutines, so the payload says
	// which request an answer belongs to.
	first.answers <- answer{seq: 1, payload: []byte("one")}
	second.answers <- answer{seq: 1, payload: []byte("two")}

	byRequest := map[string]ethlink.Echo{}
	for i := range 2 {
		echo := frames.nthEcho(t, i, 2*time.Second)
		byRequest[string(echo.Payload)] = echo
	}

	for _, tc := range []struct {
		asked string
		ip    string
		mac   string
	}{
		{"one", "10.0.2.15", "52:54:11:22:33:44"},
		{"two", "10.0.2.99", "52:54:99:88:77:66"},
	} {
		echo, ok := byRequest[tc.asked]
		if !ok {
			t.Errorf("no answer came back carrying %q, so that guest was not answered", tc.asked)
			continue
		}
		if !echo.DstIP.Equal(net.ParseIP(tc.ip)) {
			t.Errorf("the answer to %q went to %s, want %s", tc.asked, echo.DstIP, tc.ip)
		}
		if echo.DstMAC.String() != tc.mac {
			t.Errorf("the answer to %q went to %s, want %s", tc.asked, echo.DstMAC, tc.mac)
		}
	}
}

// An echo relay belongs to the guest that opened it, like every other relay. If
// the path out of the tunnel survived the session, a guest that rebooted would
// find a socket already open to the address its previous session was pinging,
// with that session's sequence numbers half used up, and the tunnel would be
// holding a translation for a machine that is gone.
func TestEndSessionClosesTheEchoPath(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, _ := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 21, 1, []byte("open")))
	if m.Relays() != 1 {
		t.Fatalf("relays = %d, want the one the ping opened", m.Relays())
	}

	m.EndSession()

	if m.Relays() != 0 {
		t.Errorf("relays = %d after the session ended, want none", m.Relays())
	}
	select {
	case <-path.closed:
	default:
		t.Error("the path through the tunnel was left open")
	}
}

// Stopping is the same promise at the other end of the process: a manager that
// has stopped holds nothing. The engine closes the stack underneath it as well,
// but shutdown that only works because of the order two Close calls happen to
// run in is the sort that breaks when someone reorders them.
func TestStopClosesOpenRelays(t *testing.T) {
	path := newFakeEchoPath()
	tunnel := &fakeEgress{echoPath: path}
	m, _ := echoManager(t, tunnel)

	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 22, 1, []byte("open")))
	m.Stop()

	if m.Relays() != 0 {
		t.Errorf("relays = %d after stopping, want none", m.Relays())
	}
	select {
	case <-path.closed:
	default:
		t.Error("the path through the tunnel survived the manager stopping")
	}
}

// A relay reads bytes that a guest, or the peer beyond the tunnel, chose byte by
// byte. If one of them trips an invariant somewhere underneath this code, the
// gateway loses the one flow that met it, gives back what it was holding, and
// writes the stack down; it does not lose every other guest's gateway. The
// oversized datagram that used to panic in the netstack's read is the shape this
// is for, and the second ping below is the point of the test.
func TestPanickingRelayTakesOnlyItselfDown(t *testing.T) {
	var logged loggedBuffer
	frames := newFramesWritten()
	m := NewManager(nil, 1, nil,
		slog.New(slog.NewTextHandler(&logged, nil)), Limits{}, frames)
	defer m.Stop()

	policy, err := config.ParseEgress(nil, nil)
	if err != nil {
		t.Fatalf("egress policy: %v", err)
	}
	m.EnableInternet(true)
	m.Own(net.ParseIP("10.0.2.2"))
	m.SetGuestSubnet(&net.IPNet{IP: net.ParseIP("10.0.2.0"), Mask: net.CIDRMask(24, 32)})
	m.SetEgressPolicy(policy)

	after := newFakeEchoPath()
	boom := &panickingEchoPath{closed: make(chan struct{})}
	m.SetEgress(&fakeEgress{echoPaths: []EchoPath{boom, after}})

	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 41, 1, []byte("boom")))

	// The log line is the last thing the panicking goroutine writes, so waiting
	// for it is also waiting for the relay to have been given back.
	testutil.Within(2*time.Second, func() bool { return logged.contains("panic recovered") })
	if !logged.contains("panic recovered") {
		t.Errorf("the panic was not written down, so the bug is hidden: %s", logged.text())
	}
	if m.Relays() != 0 {
		t.Errorf("relays = %d, want the panicking relay given back", m.Relays())
	}
	select {
	case <-boom.closed:
	default:
		t.Error("the panicking relay's path was left open, so what it held is still held")
	}

	// The manager is still itself: the next request is served, and answered to
	// the guest that asked.
	m.Inspect(guestPing(net.ParseIP("93.184.216.35"), 42, 1, []byte("after")))
	after.answers <- answer{seq: 1, payload: []byte("after")}

	echo := frames.lastEcho(t, 2*time.Second)
	if !echo.DstIP.Equal(net.ParseIP("10.0.2.15")) {
		t.Errorf("the next answer went to %s, want the guest that asked", echo.DstIP)
	}
}

// A ping is the cheapest relay a guest can ask for: one frame, no handshake, and
// the source address is the guest's to invent. Left to the relay table's own cap,
// one guest with a loop fills it with pings and the guest that comes after cannot
// open a connection. So pings are capped on their own, well under the table.
func TestPingsStopAtTheirOwnCeiling(t *testing.T) {
	const ask = defaultMaxEchoRelays + 8

	paths := make([]EchoPath, ask)
	for i := range paths {
		paths[i] = newFakeEchoPath()
	}
	tunnel := &fakeEgress{echoPaths: paths}
	m, _ := echoManager(t, tunnel)

	mac := net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44}
	for i := range ask {
		src := net.IPv4(10, 0, 2, byte(i%250)+2)
		m.Inspect(guestPingFrom(mac, src, net.ParseIP("93.184.216.34"), uint16(i), 1, []byte("x")))
	}

	if got := m.Relays(); got != defaultMaxEchoRelays {
		t.Errorf("relays = %d, want the ping ceiling, not the table's %d", got, defaultMaxRelays)
	}
	if tunnel.echoDials != defaultMaxEchoRelays {
		t.Errorf("the tunnel was dialled %d times, want it stopped at the ceiling: a ping that "+
			"will not be carried should not open a socket", tunnel.echoDials)
	}

	// The session ending closes the paths, and with them the room they held.
	m.EndSession()
	testutil.Within(2*time.Second, func() bool { return m.pingsInFlight() == 0 })
	if n := m.pingsInFlight(); n != 0 {
		t.Fatalf("pings in flight = %d after the session ended, want none", n)
	}

	m.Inspect(guestPing(net.ParseIP("93.184.216.34"), 200, 1, []byte("again")))
	if tunnel.echoDials != defaultMaxEchoRelays+1 {
		t.Errorf("the tunnel was dialled %d times, want one more after the room came back",
			tunnel.echoDials)
	}
}

// The ceiling counts pings in flight, not pings ever asked for: a path that dies
// gives its room back, so a guest whose pings fail cannot spend the ceiling for
// everybody else with a long enough session.
func TestPingsGiveTheirRoomBack(t *testing.T) {
	tunnel := &fakeEgress{echoPath: deadEchoPath{}}
	m, _ := echoManager(t, tunnel)

	for i := range 20 {
		m.Inspect(guestPing(net.ParseIP("93.184.216.34"), uint16(100+i), 1, []byte("x")))
	}

	testutil.Within(2*time.Second, func() bool { return m.pingsInFlight() == 0 })
	if n := m.pingsInFlight(); n != 0 {
		t.Errorf("pings in flight = %d, want the failed ones to have given their room back", n)
	}
	if m.Relays() != 0 {
		t.Errorf("relays = %d, want the failed paths gone", m.Relays())
	}
}
