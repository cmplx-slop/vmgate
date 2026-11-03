package nsnet

import (
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Two interfaces, a route on each, and a socket pinned to one of them. The pin
// outranks the order of the route table, and that is half of what makes a VPN
// peer's AllowedIPs the whole of a guest's reachability: the table alone would
// let a destination leave some other way. Worth pinning down at the level of
// the socket helper, where a change to the bind or the connect is visible
// without a whole gateway around it.
func TestDialUDPStaysOnThePinnedInterface(t *testing.T) {
	const (
		tunnel tcpip.NICID = 1
		link   tcpip.NICID = 2
	)

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	defer stk.Close()

	outTunnel := attach(t, stk, tunnel, "10.76.0.2")
	outLink := attach(t, stk, link, "10.0.2.2")

	// The route the table would choose is the link's: it comes first, and both
	// entries are the same prefix, which is how a default route through a VPN
	// sits next to the link's own.
	stk.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: link},
		{Destination: header.IPv4EmptySubnet, NIC: tunnel},
	})

	u, err := DialUDP(stk, tunnel, net.ParseIP("93.184.216.34"), 53)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer u.Close()

	if got := u.LocalAddr(); got.IP.String() != "10.76.0.2" {
		t.Errorf("socket's source = %s, want the pinned interface's own address", got)
	}
	if _, err := u.Write([]byte("ask")); err != nil {
		t.Fatalf("write: %v", err)
	}

	if pb := outLink.Read(); pb != nil {
		pb.DecRef()
		t.Fatal("the datagram left by the interface the route table chose, not the pinned one")
	}
	pb := outTunnel.Read()
	if pb == nil {
		t.Fatal("the pinned interface saw nothing at all")
	}
	pb.DecRef()
}

// The other half of the gate: an interface with no route for a destination
// cannot carry traffic for it, so the dial fails there rather than reaching the
// destination through an interface the guest was never meant to have. This is
// what a destination outside the peer's AllowedIPs looks like to the gateway.
func TestDialUDPNeedsARouteOnThatInterface(t *testing.T) {
	const (
		tunnel tcpip.NICID = 1
		link   tcpip.NICID = 2
	)

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	defer stk.Close()

	attach(t, stk, tunnel, "10.76.0.2")
	attach(t, stk, link, "10.0.2.2")

	// One route only, and not on the interface being dialed from.
	stk.SetRouteTable([]tcpip.Route{{
		Destination: tcpip.AddressWithPrefix{
			Address:   AddrOf(net.ParseIP("10.0.2.0")),
			PrefixLen: 24,
		}.Subnet(),
		NIC: link,
	}})

	if _, err := DialUDP(stk, tunnel, net.ParseIP("93.184.216.34"), 53); err == nil {
		t.Fatal("a destination with no route on the pinned interface was dialled anyway")
	}
}

// attach puts a channel endpoint on the stack as nic with one address, and
// returns it: the queue is where a packet leaving by that interface turns up,
// which is how these tests see which interface a dial chose.
func attach(t *testing.T, stk *stack.Stack, nic tcpip.NICID, ip string) *channel.Endpoint {
	t.Helper()

	ep := channel.New(16, 1420, "")
	if terr := stk.CreateNICWithOptions(nic, ep, stack.NICOptions{}); terr != nil {
		t.Fatalf("nic %d: %v", nic, ToError(terr))
	}
	terr := stk.AddProtocolAddress(nic, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   AddrOf(net.ParseIP(ip)),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})
	if terr != nil {
		t.Fatalf("address on nic %d: %v", nic, ToError(terr))
	}
	return ep
}
