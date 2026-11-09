package engine

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/cmplx-slop/vmgate/internal/nsnet"
)

// addAddress installs one of the gateway's own addresses on the NIC.
func (e *Engine) addAddress(ip net.IP, mask net.IPMask, primary bool) error {
	ones, _ := mask.Size()
	addr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   nsnet.AddrOf(ip),
			PrefixLen: ones,
		},
	}
	if terr := e.stk.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); terr != nil {
		return fmt.Errorf("add address %s: %w", ip, nsnet.ToError(terr))
	}
	e.log.Debug("address", "ip", ip.String(), "prefix", ones, "primary", primary)
	return nil
}

// subnet is the guest's network in the shape the route table wants.
func subnet(n *net.IPNet) tcpip.Subnet {
	ones, _ := n.Mask.Size()
	return tcpip.AddressWithPrefix{Address: nsnet.AddrOf(n.IP), PrefixLen: ones}.Subnet()
}

// routeTable is the whole of the gateway's split-tunnel policy, and its order is
// the policy: this table is matched first rather than by longest prefix, so what
// is written first wins.
//
//   - the guest's own subnet, on the interface facing QEMU, whatever the peer's
//     AllowedIPs claim. A VPN that routes 0.0.0.0/0 must not acquire a route to
//     the guest's own segment, because that lets the peer answer for a machine
//     sitting next to the guest;
//   - one route per AllowedIPs entry, pinned to the tunnel, which is the only
//     way a guest reaches anything beyond the gateway;
//   - a default back to the QEMU link, which exists so the gateway can dial into
//     the guest. A guest cannot use it: its egress sockets are pinned to the
//     tunnel, and a pinned socket's lookup only considers that interface.
func routeTable(guestNet *net.IPNet, tunnel []tcpip.Route) []tcpip.Route {
	routes := []tcpip.Route{{
		Destination: subnet(guestNet),
		NIC:         nicID,
	}}
	routes = append(routes, tunnel...)
	return append(routes, tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         nicID,
	})
}
