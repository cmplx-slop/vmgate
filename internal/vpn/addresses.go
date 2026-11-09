package vpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/cmplx-slop/vmgate/internal/nsnet"
	"github.com/cmplx-slop/vmgate/internal/wgconf"
)

// tunnelAddresses are the IPv4 addresses the configuration gives the tunnel.
// They are both what the stack installs on the NIC and what the shim will
// accept as a destination, so the two cannot drift apart.
func tunnelAddresses(conf *wgconf.Config) []tcpip.Address {
	var out []tcpip.Address
	for _, pre := range conf.Addresses {
		if !pre.Addr().Is4() {
			continue
		}
		out = append(out, tcpip.AddrFromSlice(pre.Addr().AsSlice()))
	}
	return out
}

// AddAddress gives the tunnel's interface one more address, and tells the shim
// that packets for it may be delivered too. The two move together on purpose:
// an interface that answers for an address the tunnel will not carry is an
// address that looks alive and refuses its own traffic.
//
// Nothing in the gateway calls it. A gateway is a host on the tunnel, so the
// addresses in vpn.conf are the whole of what a peer may be allowed to send to;
// a stack standing in for a network beyond the VPN needs more, and it says so
// here rather than adding an address to the interface behind the tunnel's back.
//
// Naming an address the tunnel already has is not an error.
func (t *Tunnel) AddAddress(ip net.IP) error {
	if t.closed.Load() {
		return errors.New("vpn: tunnel is closed")
	}
	if t.stk == nil {
		return errors.New("vpn: tunnel is not attached")
	}
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("vpn: %s is not IPv4, and the tunnel speaks IPv4", ip)
	}
	na, ok := netip.AddrFromSlice(v4)
	if !ok {
		return fmt.Errorf("vpn: %s is not an address the tunnel can hold", ip)
	}
	if err := wgconf.CheckInterfaceAddress(na); err != nil {
		return fmt.Errorf("vpn: address %s %v", ip, err)
	}

	addr := tcpip.AddrFromSlice(v4)
	if t.shim.owns(addr) {
		return nil
	}

	terr := t.stk.AddProtocolAddress(t.nic, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: addr, PrefixLen: 32,
		},
	}, stack.AddressProperties{})
	if terr != nil {
		return fmt.Errorf("vpn: address %s: %v", ip, nsnet.ToError(terr))
	}
	t.shim.serve(addr)
	return nil
}

// Routes is one route per AllowedIPs entry, pinned to the tunnel's interface.
// This is the whole of the gateway's split-tunnel policy: a destination with no
// route here cannot be reached at all, because the egress sockets are pinned to
// this interface.
//
// Attach must have run: the routes name an interface number.
func (t *Tunnel) Routes() []tcpip.Route {
	var out []tcpip.Route
	for _, pre := range t.conf.V4Routes() {
		out = append(out, tcpip.Route{
			Destination: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(pre.Addr().AsSlice()),
				PrefixLen: pre.Bits(),
			}.Subnet(),
			NIC: t.nic,
		})
	}
	return out
}

// parseV4 reads a numeric IPv4 address. What reaches the tunnel came out of a
// packet header, so there is no name to look up here.
func parseV4(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("vpn: %q is not an address", addr)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("vpn: %s is not IPv4, and the tunnel speaks IPv4", addr)
	}
	return ip.To4(), nil
}

// parseV4Port reads an "1.2.3.4:5678" address. Addresses reaching the tunnel
// are always numeric: they came from a packet header.
func parseV4Port(addr string) (net.IP, uint16, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, fmt.Errorf("vpn: %q is not host:port", addr)
	}
	ip, err := parseV4(host)
	if err != nil {
		return nil, 0, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, 0, fmt.Errorf("vpn: %q is not a port", port)
	}
	return ip, uint16(n), nil
}
