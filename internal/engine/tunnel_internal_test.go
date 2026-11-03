package engine

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/config"
	"vmgate/internal/wgconf"
)

// key is a well formed wg key for a test that cares about addresses rather than
// the maths: wgconf checks the shape of a key, not that it belongs to a curve.
func key(t *testing.T) string {
	t.Helper()

	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// confOf parses a tunnel configuration for these addresses.
func confOf(t *testing.T, addresses string) *wgconf.Config {
	t.Helper()

	text := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + key(t),
		"Address = " + addresses,
		"[Peer]",
		"PublicKey = " + key(t),
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")

	c, err := wgconf.Parse("vpn.conf", strings.NewReader(text))
	if err != nil {
		t.Fatalf("vpn conf: %v", err)
	}
	return c
}

// The tunnel installs every address it is given, so every one of them has to be
// checked against the guest's subnet: a borrowed vpn.conf with a second address
// inside 10.0.2.0/24 is enough to let the peer answer for a machine on the
// guest's own segment, and the first address looks perfectly reasonable.
func TestCheckTunnelLooksAtEveryAddress(t *testing.T) {
	e := &Engine{
		cfg: config.Config{
			GatewayIP: net.ParseIP("10.0.2.2"),
			Mask:      net.CIDRMask(24, 32),
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	if err := e.checkTunnel(confOf(t, "10.76.0.1/32")); err != nil {
		t.Fatalf("a tunnel clear of the guest's subnet: %v", err)
	}

	for _, addresses := range []string{
		"10.76.0.1/32, 10.0.2.9/32", // the mistake, in the second place
		"10.0.2.9/32, 10.76.0.1/32", // and in the first
		"fd00::1/128, 10.0.2.9/32",  // with an IPv6 address in front of it
	} {
		err := e.checkTunnel(confOf(t, addresses))
		if err == nil {
			t.Fatalf("%q was accepted: the tunnel would answer for part of the guest's subnet", addresses)
		}
		if !strings.Contains(err.Error(), "inside the guest's subnet") {
			t.Errorf("%q failed with %q, want the subnet complaint", addresses, err)
		}
	}
}

// The same address named twice is not a tunnel with two addresses; it is a
// configuration that has lost track of what it says.
func TestCheckTunnelRefusesADuplicateAddress(t *testing.T) {
	e := &Engine{
		cfg: config.Config{
			GatewayIP: net.ParseIP("10.0.2.2"),
			Mask:      net.CIDRMask(24, 32),
		},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	err := e.checkTunnel(confOf(t, "10.76.0.1/32, 10.76.0.1/24"))
	if err == nil {
		t.Fatal("the same address twice was accepted")
	}
	if !strings.Contains(err.Error(), "more than once") {
		t.Errorf("failed with %q, want the duplicate complaint", err)
	}
}

// The order of the route table is the policy, because the table is matched first
// and not by longest prefix. End to end, a mistake here looks like a guest that
// cannot be reached, or one whose own segment is answered for by the VPN peer,
// which is a long way from the line that caused it: so the order is asserted
// here, where building it is all the function does.
func TestRouteTableKeepsTheGuestsOwnSegmentFirst(t *testing.T) {
	guestNet := &net.IPNet{IP: net.ParseIP("10.0.2.0"), Mask: net.CIDRMask(24, 32)}

	routes := routeTable(guestNet, []tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: vpnNIC},
		{Destination: subnet(&net.IPNet{IP: net.ParseIP("10.76.0.0"), Mask: net.CIDRMask(24, 32)}), NIC: vpnNIC},
	})

	if len(routes) != 4 {
		t.Fatalf("%d routes, want the guest's, the tunnel's two and the gateway's own:\n%v", len(routes), routes)
	}

	// First: the guest's subnet, on the interface facing QEMU, ahead of the
	// tunnel's claim on everything.
	if routes[0].NIC != nicID || routes[0].Destination.String() != "10.0.2.0/24" {
		t.Errorf("route 1 = %v on nic %d, want 10.0.2.0/24 on the QEMU link",
			routes[0].Destination, routes[0].NIC)
	}

	// Last: a default on the QEMU link, for the gateway dialling the guest.
	last := routes[len(routes)-1]
	if last.NIC != nicID || last.Destination != header.IPv4EmptySubnet {
		t.Errorf("last route = %v on nic %d, want the default on the QEMU link",
			last.Destination, last.NIC)
	}

	// The tunnel's routes, including a 0.0.0.0/0 that must sit behind the
	// gateway's own, and pinned to the tunnel rather than the link.
	for i, r := range routes[1 : len(routes)-1] {
		if r.NIC != vpnNIC {
			t.Errorf("tunnel route %d is on nic %d, want the tunnel", i+1, r.NIC)
		}
	}
	if routes[1].Destination != header.IPv4EmptySubnet {
		t.Errorf("the tunnel's default is not where it was put, at route 2: %v", routes[1].Destination)
	}
}

// Which resolver list the gateway uses is invisible to the guest: its lookups are
// answered either way, so a change that quietly ignored dns.upstreams, or that
// fell back to the host too eagerly, would fail no other test. The order is
// asserted where the choice is made.
func TestResolversAreChosenInTheAgreedOrder(t *testing.T) {
	tunnel := []net.IP{net.ParseIP("10.76.0.1")}

	got, from, err := resolversFor([]string{"1.1.1.1", "8.8.8.8:5353"}, tunnel)
	if err != nil {
		t.Fatalf("dns.upstreams: %v", err)
	}
	if from != fileResolvers {
		t.Errorf("resolvers came from %q, want %q", from, fileResolvers)
	}
	if joined := strings.Join(got, ","); joined != "1.1.1.1:53,8.8.8.8:5353" {
		t.Errorf("dns.upstreams = %s, want both names as written with their ports", joined)
	}

	got, from, err = resolversFor(nil, tunnel)
	if err != nil {
		t.Fatalf("vpn.conf: %v", err)
	}
	if from != tunnelResolvers {
		t.Errorf("resolvers came from %q, want %q", from, tunnelResolvers)
	}
	if joined := strings.Join(got, ","); joined != "10.76.0.1:53" {
		t.Errorf("the tunnel's resolver = %s, want 10.76.0.1:53", joined)
	}

	got, from, err = resolversFor(nil, nil)
	if err != nil {
		t.Fatalf("the host: %v", err)
	}
	if from != hostResolvers {
		t.Errorf("resolvers came from %q, want %q", from, hostResolvers)
	}
	if len(got) == 0 {
		t.Error("no resolvers at all: a guest would be handed a resolver list that cannot answer")
	}

	// A resolver named by hostname is refused rather than looked up: the only
	// resolver this process has lives inside the tunnel.
	if _, _, err := resolversFor([]string{"resolver.example.com"}, tunnel); err == nil {
		t.Error("an upstream named by hostname was accepted")
	}
}
