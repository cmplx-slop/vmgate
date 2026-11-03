package dhcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"vmgate/internal/testutil"
)

func testServer() *Server {
	return NewServer(ServerConfig{
		Gateway:   net.ParseIP("10.0.2.2"),
		DNS:       []net.IP{net.ParseIP("10.0.2.3")},
		Mask:      net.CIDRMask(24, 32),
		Pool:      Pool{Start: net.ParseIP("10.0.2.15"), Size: 2},
		LeaseTime: time.Hour,
		Domain:    "vmgate",
		MTU:       1500,
	})
}

func client(mac []byte, msgType byte, xid uint32, requested net.IP) *Message {
	opts := Options{
		{Code: OptMessageType, Value: []byte{msgType}},
		{Code: OptParamRequest, Value: []byte{OptSubnetMask, OptRouter, OptDNS, OptDomainName}},
	}
	if requested != nil {
		opts.Set(OptRequestedIP, requested.To4())
	}
	return &Message{
		Op:      OpBootpRequest,
		HType:   1,
		HLen:    6,
		XID:     xid,
		Flags:   FlagBroadcast,
		CHAddr:  mac,
		Options: opts,
	}
}

// TestFourWayWalk checks the DISCOVER/OFFER/REQUEST/ACK exchange and the
// options a guest needs to bring its interface up.
func TestFourWayWalk(t *testing.T) {
	s := testServer()
	mac := testutil.MAC(t, "52:54:00:12:34:56")

	offer, ok := s.Handle(client(mac, Discover, 0xabcd, nil))
	if !ok {
		t.Fatal("no offer for DISCOVER")
	}
	if got := offer.Type(); got != Offer {
		t.Fatalf("offer type = %d, want %d", got, Offer)
	}
	if !offer.YourIP.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Fatalf("offer yiaddr = %v, want 10.0.2.15", offer.YourIP)
	}
	if offer.XID != 0xabcd {
		t.Fatalf("offer xid = %x, want abcd", offer.XID)
	}
	if offer.ServerIP == nil || !offer.ServerIP.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Fatalf("offer siaddr = %v, want the gateway", offer.ServerIP)
	}
	if sid := offer.Options.IP(OptServerID); sid == nil || !sid.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Fatalf("option 54 = %v, want the gateway", sid)
	}
	if m := offer.Options.IP(OptSubnetMask); m == nil || net.IPMask(m).String() != "fffffe00" && !bytes.Equal(m, net.IPv4Mask(255, 255, 255, 0)) {
		t.Fatalf("option 1 = %v, want 255.255.255.0", m)
	}
	if r := offer.Options.IP(OptRouter); r == nil || !r.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Fatalf("option 3 = %v, want the gateway", r)
	}
	if d := offer.Options.IP(OptDNS); d == nil || !d.Equal(net.IPv4(10, 0, 2, 3)) {
		t.Fatalf("option 6 = %v, want the DNS address", d)
	}
	if lt, ok := offer.Options.U32(OptLeaseTime); !ok || lt != uint32(time.Hour/time.Second) {
		t.Fatalf("option 51 = %d, want %d", lt, uint32(time.Hour/time.Second))
	}
	if _, ok := offer.Options.U32(OptRenewalTime); !ok {
		t.Fatal("option 58 (renewal time) missing")
	}
	if dn, ok := offer.Options.Get(OptDomainName); !ok || string(dn) != "vmgate" {
		t.Fatalf("option 15 = %q, want vmgate", dn)
	}

	// The wire format has to survive a round trip, because that is what the
	// guest actually parses.
	wire := offer.Marshal()
	if len(wire) < 300 {
		t.Fatalf("marshalled offer is %d bytes, want at least 300", len(wire))
	}
	back, err := Parse(wire)
	if err != nil {
		t.Fatalf("reparse offer: %v", err)
	}
	if !back.YourIP.Equal(offer.YourIP) || back.Type() != Offer {
		t.Fatalf("round trip changed the offer: %+v", back)
	}

	req := client(mac, Request, 0xabce, offer.YourIP)
	ack, ok := s.Handle(req)
	if !ok {
		t.Fatal("no reply to REQUEST")
	}
	if ack.Type() != Ack {
		t.Fatalf("REQUEST reply type = %d, want ACK", ack.Type())
	}
	if !ack.YourIP.Equal(offer.YourIP) {
		t.Fatalf("ACK yiaddr = %v, want %v", ack.YourIP, offer.YourIP)
	}

	leases := s.Leases()
	if len(leases) != 1 || !leases[0].IP.Equal(offer.YourIP) {
		t.Fatalf("leases = %v, want one for %v", leases, offer.YourIP)
	}
	if !leases[0].Expiry.After(time.Now()) {
		t.Fatalf("lease %v already expired", leases[0])
	}
}

// TestNakForForeignAddress checks that a client cannot claim somebody else's
// address.
func TestNakForForeignAddress(t *testing.T) {
	s := testServer()
	a := testutil.MAC(t, "52:54:00:00:00:01")
	b := testutil.MAC(t, "52:54:00:00:00:02")

	offerA, _ := s.Handle(client(a, Discover, 1, nil))
	if offerA.YourIP == nil {
		t.Fatal("no address offered to the first client")
	}

	rep, ok := s.Handle(client(b, Request, 2, offerA.YourIP))
	if !ok {
		t.Fatal("no reply to a REQUEST for a taken address")
	}
	if rep.Type() != Nak {
		t.Fatalf("reply type = %d, want NAK", rep.Type())
	}
	if len(s.Leases()) != 1 {
		t.Fatalf("leases = %v, want only the first client's", s.Leases())
	}
}

// TestReleaseFreesAddress checks that a released lease can be reused.
func TestReleaseFreesAddress(t *testing.T) {
	s := testServer()
	a := testutil.MAC(t, "52:54:00:00:00:0a")
	b := testutil.MAC(t, "52:54:00:00:00:0b")

	first, _ := s.Handle(client(a, Discover, 1, nil))
	second, _ := s.Handle(client(b, Discover, 2, nil))
	if first.YourIP.Equal(second.YourIP) {
		t.Fatalf("both clients got %v", first.YourIP)
	}

	if rep, ok := s.Handle(client(a, Release, 3, first.YourIP)); ok {
		t.Fatalf("RELEASE produced a reply: %v", rep)
	}
	if len(s.Leases()) != 1 {
		t.Fatalf("leases after RELEASE = %d, want 1", len(s.Leases()))
	}

	c := testutil.MAC(t, "52:54:00:00:00:0c")
	if _, ok := s.Handle(client(c, Discover, 4, first.YourIP)); !ok {
		t.Fatal("the freed address could not be reused")
	}
}

// TestEmptyPool checks the server does not crash or invent addresses once the
// pool is exhausted.
// A pool that has run out answers nothing at all. An OFFER carrying no address
// is a message the client cannot use, and it only invites a REQUEST that can be
// answered no better than with a NAK, so a server with nothing to hand out stays
// quiet and the client retries on its own timer.
func TestEmptyPool(t *testing.T) {
	s := testServer() // pool: 10.0.2.15, 10.0.2.16

	var got []*Message
	for i, mac := range []string{"52:54:00:00:00:11", "52:54:00:00:00:12", "52:54:00:00:00:13"} {
		rep, ok := s.Handle(client(testutil.MAC(t, mac), Discover, uint32(i+1), nil))
		if !ok {
			if i < 2 {
				t.Fatalf("client %d got no reply at all", i)
			}
			continue
		}
		got = append(got, rep)
	}
	if len(got) != 2 {
		t.Fatalf("replies = %d, want one per address in the pool and none for the third client", len(got))
	}
	if !got[0].YourIP.Equal(net.IPv4(10, 0, 2, 15)) || !got[1].YourIP.Equal(net.IPv4(10, 0, 2, 16)) {
		t.Fatalf("pool handed out %v and %v", got[0].YourIP, got[1].YourIP)
	}
}

// TestPinMAC checks -guest-mac pinning.
func TestPinMAC(t *testing.T) {
	cfg := ServerConfig{
		Gateway: net.ParseIP("10.0.2.2"),
		Mask:    net.CIDRMask(24, 32),
		Pool:    Pool{Start: net.ParseIP("10.0.2.15"), Size: 2},
		PinMAC:  testutil.MAC(t, "52:54:00:00:00:ff"),
	}
	cfg.PinMAC = net.HardwareAddr(cfg.PinMAC)
	s := NewServer(cfg)

	if _, ok := s.Handle(client(testutil.MAC(t, "52:54:00:00:00:01"), Discover, 1, nil)); ok {
		t.Fatal("unpinned client was served")
	}
	if _, ok := s.Handle(client(testutil.MAC(t, "52:54:00:00:00:ff"), Discover, 2, nil)); !ok {
		t.Fatal("pinned client was refused")
	}
}
