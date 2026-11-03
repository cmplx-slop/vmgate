package engine_test

import (
	"context"
	"net"
	"testing"
	"time"

	"vmgate/internal/config"
	"vmgate/internal/dhcp"
	"vmgate/internal/fixture"
	"vmgate/internal/testutil"
)

// A destination on the guest's own segment is not the tunnel's to carry. Left to
// the route table, the peer could be handed any address in the guest's LAN and
// answer for it, which turns a VPN peer into a machine on the guest's network.
func TestGuestSegmentIsNeverRelayed(t *testing.T) {
	const neighbour = "10.0.2.99"

	n := fixture.New(t, nil)
	// The far side takes the guest's address, which it is allowed to do: this
	// is the other half of the attack, and it has to fail on our side.
	n.VPN.ServeTCP(neighbour, 80, "far:")
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, neighbour, 80)
	if err == nil {
		defer conn.Close()
		if _, err := conn.Write([]byte("mine?\n")); err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 32)
			if rd, rerr := conn.Read(buf); rd > 0 {
				t.Fatalf("the peer answered for an address on the guest's own segment: %q", buf[:rd])
			} else if rerr == nil {
				t.Fatal("the peer answered for an address on the guest's own segment")
			}
		}
	}
	if got := n.Eng.Stats().Denied; got == 0 {
		t.Error("a destination on the guest's own segment was not counted as refused")
	}
	if got := n.Eng.Stats().Relays; got != 0 {
		t.Errorf("relays = %d: nothing should be listening for the guest's own segment", got)
	}
}

// The gateway's own tunnel address belongs to the gateway. A guest that dials it
// has to meet the stack, not a relay that dials the address back into the
// tunnel, holding a slot and a connection against the caps.
func TestTunnelAddressIsOurs(t *testing.T) {
	n := fixture.New(t, nil)
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if _, err := n.DialTCP(ctx, n.VPN.TunnelIP.String(), 80); err == nil {
		t.Fatal("something answered on the gateway's own tunnel address")
	}
	if got := n.Eng.Stats().Relays; got != 0 {
		t.Errorf("relays = %d: the gateway must not dial its own tunnel address", got)
	}
}

// TestInternetTCPRelay covers gateway.internet: the guest dials an address that
// is neither ours nor forwarded, and the gateway appears with a listener for it
// just in time to take the SYN. The answer comes back through the tunnel, which
// is the only path a guest has.
func TestInternetTCPRelay(t *testing.T) {
	const fake = "93.184.216.34"

	n := fixture.New(t, nil)
	n.VPN.ServeTCP(fake, 80, "internet:")
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, fake, 80)
	if err != nil {
		t.Fatalf("guest dial %s:80: %v", fake, err)
	}
	defer conn.Close()

	if got, want := exchange(t, conn, "http"), "internet:http"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := n.Eng.Stats().Relays; got < 1 {
		t.Fatalf("no on-demand relay was installed (relays=%d)", got)
	}

	// The tunnel has to have met its peer by now, and to have counted the
	// bytes: that is what the status line reports to an operator.
	if !n.VPN.Handshake(5 * time.Second) {
		t.Fatal("the far side never completed a handshake")
	}
	if s := n.Eng.Stats(); s.VPN.Rx == 0 || s.VPN.Tx == 0 || s.VPN.ListenPort == 0 {
		t.Fatalf("tunnel counters rx=%d tx=%d listen_port=%d: the gateway's own tunnel never reported the traffic it carried",
			s.VPN.Rx, s.VPN.Tx, s.VPN.ListenPort)
	}
}

// TestInternetUDPRelay is the datagram version of the same trick.
func TestInternetUDPRelay(t *testing.T) {
	const fake = "198.51.100.7"

	n := fixture.New(t, nil)
	n.VPN.ServeUDP(fake, 53, "echo:")
	n.Configure()

	reply, err := n.Exchange([]byte("whois"), net.ParseIP(fake), 53, 20*time.Second)
	if err != nil {
		t.Fatalf("guest udp exchange: %v", err)
	}
	if got := string(reply); got != "echo:whois" {
		t.Fatalf("got %q, want %q", got, "echo:whois")
	}
}

// TestTunnelOutsideAllowedIPs is the other half of the tunnel policy: a
// destination the peer will not carry has no route, and the gateway says so
// rather than sending it out some other way.
func TestTunnelOutsideAllowedIPs(t *testing.T) {
	const inside = "198.51.100.7"
	const outside = "93.184.216.34"

	n := fixture.NewAgainst(t, []string{"198.51.100.0/24"}, nil)
	n.VPN.ServeTCP(inside, 80, "inside:")
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, inside, 80)
	if err != nil {
		t.Fatalf("dial %s:80, which the tunnel carries: %v", inside, err)
	}
	defer conn.Close()
	if got, want := exchange(t, conn, "there"), "inside:there"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// The destination outside AllowedIPs. The guest's own connection is taken
	// either way, because a relay exists before anything is dialled: what has
	// to differ is what comes back. Nothing can be, so the gateway closes it.
	conn, err = n.DialTCP(ctx, outside, 80)
	if err == nil {
		defer conn.Close()
		if _, err := conn.Write([]byte("there?\n")); err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 32)
			if rd, rerr := conn.Read(buf); rd > 0 {
				t.Fatalf("a destination outside AllowedIPs was reached: %q", buf[:rd])
			} else if rerr == nil {
				t.Fatal("a destination outside AllowedIPs was reached")
			}
		}
	}
	if got := n.Eng.Stats().Denied; got == 0 {
		t.Error("a destination with no tunnel route was not counted as refused")
	}
}

// TestTunnelLowersTheLinkMTU: a guest that sizes its packets for 1500 would have
// them fragmented on the way into a 1420 byte tunnel, so the gateway hands out
// the tunnel's number instead.
func TestTunnelLowersTheLinkMTU(t *testing.T) {
	r := fixture.Link(t, func(f *config.File) {
		f.Network.MTU = 1500
	})

	if got, want := r.Eng.MTU(), r.VPN.MTU; got != want {
		t.Fatalf("link MTU = %d, want the tunnel's %d", got, want)
	}

	// And the lease says the same thing on the wire, which is the only way the
	// guest ever finds out.
	mac := testutil.MAC(t, "52:54:00:aa:bb:cc")
	xid := uint32(0x2468)

	disc := dhcp.Message{
		Op: dhcp.OpBootpRequest, HType: 1, HLen: 6, XID: xid,
		Flags:  dhcp.FlagBroadcast,
		CHAddr: mac,
		Options: dhcp.Options{
			{Code: dhcp.OptMessageType, Value: []byte{dhcp.Discover}},
		},
	}
	if err := r.Frames.WriteFrame(ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, disc.Marshal())); err != nil {
		t.Fatalf("write DISCOVER: %v", err)
	}
	offer := readDHCP(t, r.Frames)

	req := dhcp.Message{
		Op: dhcp.OpBootpRequest, HType: 1, HLen: 6, XID: xid,
		Flags:  dhcp.FlagBroadcast,
		CHAddr: mac,
		Options: dhcp.Options{
			{Code: dhcp.OptMessageType, Value: []byte{dhcp.Request}},
			{Code: dhcp.OptRequestedIP, Value: offer.YourIP.To4()},
			{Code: dhcp.OptServerID, Value: r.Cfg.GatewayIP.To4()},
		},
	}
	if err := r.Frames.WriteFrame(ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, req.Marshal())); err != nil {
		t.Fatalf("write REQUEST: %v", err)
	}
	ack := readDHCP(t, r.Frames)
	if ack.Type() != dhcp.Ack {
		t.Fatalf("second reply is %s, want ACK", dhcp.TypeString(ack.Type()))
	}

	got := dhcpOptionUint16(t, ack, dhcp.OptInterfaceMTU)
	if got != r.VPN.MTU {
		t.Fatalf("DHCP handed out MTU %d, want the tunnel's %d", got, r.VPN.MTU)
	}
}

// TestDNSGoesThroughTheTunnel: the resolvers named in vpn.conf are asked from
// inside the stack, so a lookup leaves the same way the guest's traffic does.
func TestDNSGoesThroughTheTunnel(t *testing.T) {
	n := fixture.New(t, nil)
	// The fixture's vpn.conf names the far side as the resolver.
	n.VPN.ServeDNS(n.VPN.FarIP.String(), map[string]string{"example.com": "198.51.100.9"})
	n.Configure()

	msg := dnsQuery("example.com")
	reply, err := n.Exchange(msg, n.Cfg.DNSIP, 53, 20*time.Second)
	if err != nil {
		t.Fatalf("guest dns query: %v", err)
	}
	answers, ip := dnsAnswers(t, reply)
	if answers != 1 {
		t.Fatalf("answers = %d, want 1 (% x)", answers, reply)
	}
	if want := net.ParseIP("198.51.100.9"); !ip.Equal(want) {
		t.Fatalf("answer = %v, want %v from beyond the tunnel", ip, want)
	}
}

// TestNoInternet checks that gateway.internet = false leaves arbitrary destinations
// unreachable, which is the point of the flag.
func TestNoInternet(t *testing.T) {
	n := fixture.New(t, func(f *config.File) {
		f.Gateway.Internet = false
	})
	n.Configure()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := n.DialTCP(ctx, "93.184.216.34", 80)
	if err == nil {
		conn.Close()
		t.Fatal("a connection to the internet succeeded with gateway.internet off")
	}
}
