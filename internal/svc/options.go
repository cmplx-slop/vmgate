package svc

import (
	"net"

	"github.com/cmplx-slop/vmgate/internal/config"
)

// EnableInternet turns on-demand relaying of arbitrary destination addresses
// on or off; this is gateway.internet.
func (m *Manager) EnableInternet(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.internet = on
}

// SetEgressPolicy installs the policy that decides which destinations an
// on-demand relay may dial at all. Explicit [[service]] targets are not
// covered: they are the operator's own choice.
func (m *Manager) SetEgressPolicy(p *config.EgressPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = p
}

// SetGuestSubnet names the network the guest is on, so that a destination
// inside it is never relayed. The route table already sends that subnet to the
// QEMU link, but an egress socket is pinned to the tunnel and the pin outranks
// the order of the table: without this a guest could dial a machine on its own
// segment, and the peer beyond the VPN could answer for it.
func (m *Manager) SetGuestSubnet(subnet *net.IPNet) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if subnet != nil && subnet.IP.To4() != nil && len(subnet.Mask) == net.IPv4len {
		m.guestNet = subnet
		return
	}

	// A guard that cannot be armed has to be said out loud: the guest can
	// then dial its own segment and whatever sits beyond the VPN answers,
	// which is exactly the thing this function exists to prevent.
	m.guestNet = nil
	m.log.Warn("svc: cannot guard the guest's own segment",
		"subnet", subnet,
		"why", "a destination inside the guest's subnet would be relayed into the tunnel")
}

// SetEgress installs the path that a destination the guest chose is reached
// by, which is the VPN tunnel. Without one, dialling a guest's destination is
// refused rather than attempted: a missing tunnel must never mean "use the
// host's connection instead".
func (m *Manager) SetEgress(e Egress) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnel = e
}
