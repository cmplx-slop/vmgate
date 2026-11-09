package svc

import (
	"errors"
	"net"
	"time"

	"github.com/cmplx-slop/vmgate/internal/nsnet"
)

// errNoTunnel is what a guest destination is answered with when no tunnel is
// installed. It should be unreachable in a running gateway, which refuses to
// start without a vpn.conf; it exists so a wiring mistake fails rather than
// reaching the host's network.
var errNoTunnel = errors.New("svc: no tunnel to dial through")

// subnetBroadcast is the directed broadcast address of a subnet: the network
// address with every host bit set. The gateway claims it, so that a guest
// sending to it is not treated as a destination to relay, and ICMP still
// refuses to answer out of it.
func subnetBroadcast(n *net.IPNet) net.IP {
	ip, mask := n.IP.To4(), net.IP(n.Mask).To4()
	if ip == nil || mask == nil {
		return nil
	}
	out := make(net.IP, net.IPv4len)
	for i := range out {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

// refusedDial counts a destination the tunnel would not carry. A destination
// outside the peer's AllowedIPs has no route, and counting it with the ones the
// policy refused is what makes "why can the guest not reach that?" answerable
// from the log.
func (m *Manager) refusedDial(proto, hostAddr string, err error) {
	why := "dial failed"
	if nsnet.NoRoute(err) {
		why = "no route through the tunnel"
	}
	m.deny(hostAddr, why, "proto", proto, "err", err)
}

// hostKeepAlive asks the host kernel to notice a peer that disappeared without
// closing, which is what keeps an abandoned splice from holding a socket and
// two goroutines for the rest of the process's life.
func hostKeepAlive(c net.Conn, d time.Duration) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(d)
	}
}
