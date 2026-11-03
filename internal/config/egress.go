package config

import (
	"fmt"
	"net"
	"strings"
)

// reservedEgress are the destinations the gateway refuses to dial on the
// guest's behalf when gateway.internet is on, unless the operator names the
// range in gateway.allow_egress. They are the ranges that belong to the host
// itself or to nobody at all, and reaching them from a guest is almost never
// what the operator meant: link-local in particular carries the cloud
// metadata endpoint, which is the classic prize of a network-reachable guest.
//
// Private networks (RFC1918) are deliberately not in the list: reaching a lab
// network is a normal thing to want, and gateway.deny_egress is there for the
// operator who does not want it. Neither are the IANA documentation ranges:
// refusing them would be surprising rather than safer, since nothing routes
// there anyway and they are the conventional placeholder addresses.
var reservedEgress = []string{
	"0.0.0.0/8",      // this host, this network
	"127.0.0.0/8",    // the host's loopback
	"169.254.0.0/16", // link-local, where the metadata service lives
	"100.64.0.0/10",  // shared address space: carrier NAT and overlays
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, including the broadcast address
}

// EgressPolicy decides which destinations the gateway may dial because a guest
// asked for them. It is consulted for the on-demand relays only: an explicit
// [[service]] target is the operator's choice and is never questioned.
//
// allow wins over deny, so an operator can lift one of the reserved ranges;
// deny adds to it. An entry is an address or a CIDR: a bare prefix length is not
// accepted, because allow_egress = ["0"] would mean "everything" and is far too
// easy to write by accident.
type EgressPolicy struct {
	allow    []*net.IPNet
	deny     []*net.IPNet
	reserved []*net.IPNet

	// The operator's own ranges, kept apart from the built-in ones so the
	// startup log does not attribute our defaults to them.
	customAllow []string
	customDeny  []string
}

// ParseEgress builds the policy from the operator's two lists and the built-in
// reserved ranges.
func ParseEgress(allow, deny []string) (*EgressPolicy, error) {
	p := &EgressPolicy{}

	var err error
	if p.allow, err = parseNets(allow, "gateway.allow_egress"); err != nil {
		return nil, err
	}
	if p.deny, err = parseNets(deny, "gateway.deny_egress"); err != nil {
		return nil, err
	}
	p.customAllow, p.customDeny = netStrings(p.allow), netStrings(p.deny)

	p.reserved, err = parseNets(reservedEgress, "reserved")
	if err != nil {
		return nil, err
	}
	p.deny = append(p.deny, p.reserved...)
	return p, nil
}

// Allows reports whether the gateway may dial ip on the guest's behalf. A nil
// policy allows everything, which is what the paths that do not consult a
// policy expect.
func (p *EgressPolicy) Allows(ip net.IP) bool { return p.BlockedBy(ip) == "" }

// BlockedBy names the range that refuses ip, or "" when nothing does. It is a
// separate question from Allows because the answer belongs in the log.
func (p *EgressPolicy) BlockedBy(ip net.IP) string {
	if p == nil || ip == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		// Only IPv4 guests exist here, and an address that is not IPv4 has no
		// route through the gateway anyway.
		return "not IPv4"
	}
	for _, n := range p.allow {
		if n.Contains(v4) {
			return ""
		}
	}
	for _, n := range p.deny {
		if n.Contains(v4) {
			return n.String()
		}
	}
	return ""
}

// Custom lists the ranges the operator wrote down, which is what the startup
// log repeats: the built-in ones are already refused without being named.
func (p *EgressPolicy) Custom() (allow, deny []string) {
	if p == nil {
		return nil, nil
	}
	return p.customAllow, p.customDeny
}

// LiftsReserved reports whether an allow entry reopens one of the built-in
// ranges. That deserves to be said out loud at startup: the usual way to do it
// is an entry that covers the whole world, and the result is that a guest can
// reach the host's own services and the metadata endpoint again.
func (p *EgressPolicy) LiftsReserved() bool {
	if p == nil {
		return false
	}
	for _, entry := range p.allow {
		for _, r := range p.reserved {
			// Two CIDR blocks either are disjoint or one contains the other,
			// so testing containment both ways is the same as testing for any
			// overlap: an allow entry naming one address inside link-local
			// lifts that range just as much as naming the range does.
			if entry.Contains(r.IP) || r.Contains(entry.IP) {
				return true
			}
		}
	}
	return false
}

// Reserved lists the built-in ranges.
func Reserved() []string { return append([]string(nil), reservedEgress...) }

func parseNets(list []string, field string) ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(list))
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, fmt.Errorf("%s has an empty entry", field)
		}
		if ip := net.ParseIP(entry); ip != nil {
			// A bare address names that one address.
			if v4 := ip.To4(); v4 != nil {
				out = append(out, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
				continue
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			continue
		}
		if _, n, err := net.ParseCIDR(entry); err == nil {
			out = append(out, n)
			continue
		}
		return nil, fmt.Errorf("%s: %q is not an address or a network", field, entry)
	}
	return out, nil
}

func netStrings(nets []*net.IPNet) []string {
	if len(nets) == 0 {
		return nil
	}
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	return out
}
