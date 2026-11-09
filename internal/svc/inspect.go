package svc

import "github.com/cmplx-slop/vmgate/internal/ethlink"

// Inspect is the hook the link layer calls for every inbound frame. It gives
// the on-demand relays a chance to appear before the stack sees the packet, and
// it answers ICMP echo itself.
//
// It runs on the link's read goroutine, so everything the gateway does with a
// guest's frames happens here: a handler that blocks stops that guest's whole
// inbound path, DHCP and TCP included. What is done below is cheap by
// construction — a listener is created and the dialling happens on the relay's
// own goroutine — with one exception worth knowing before changing anything:
// the echo path dials and sends through the tunnel on this goroutine
// (Manager.relayEcho), which holds only because the tunnel's endpoint never
// blocks on a write.
//
// The result says whether the stack may see the frame. An echo never may,
// because the gateway answers those at the frame level, and neither may a
// fragment of one, for the same reason: the stack puts the datagram back
// together and its always-on echo responder answers it, spoofed from whatever
// address was pinged, no matter what the policy says about that address. TCP
// and UDP fragments are still handed over, because a flow the guest fragmented
// has to keep working and nothing in the stack answers for an address the way
// that responder does. Everything else goes to the stack, including a frame
// whose destination was refused: with no listener behind it TCP answers with a
// reset and UDP with an unreachable, which reads as "nothing here" rather than
// the silence a dropped frame would be.
func (m *Manager) Inspect(fr []byte) bool {
	if echo, ok := ethlink.ParseEcho(fr); ok {
		m.echo(echo)
		return false
	}
	if dst, ok := ethlink.ICMPFragment(fr); ok {
		// Refused here rather than delivered, so that the lie above is not
		// available to a guest that merely splits its ping in two, and so that
		// it shows up in the counters instead of being invisible to them.
		m.deny(dst.String(), "an ICMP fragment this gateway does not reassemble",
			"proto", "icmp")
		return false
	}

	flow, ok := ethlink.Classify(fr)
	if !ok {
		return true
	}
	if m.ownAddress(flow) {
		return true
	}
	m.relayForGuest(flow)
	return true
}

// ownAddress reports a frame aimed at an address the gateway serves itself.
// True means the frame is the stack's business: those addresses have listeners,
// installed when the configuration was read, and a port the guest picks for one
// of them is not something the gateway starts relaying on the guest's behalf.
func (m *Manager) ownAddress(flow ethlink.Flow) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.own[flow.DstIP.String()]
}

// relayForGuest opens the listener a destination of the guest's own choosing
// needs, so that the first packet of a flow already has somewhere to go. A
// destination here was picked by the guest, which is why every guardrail in
// this package sits on this path.
func (m *Manager) relayForGuest(flow ethlink.Flow) {
	m.mu.Lock()
	internet := m.internet
	policy := m.policy
	guestNet := m.guestNet
	m.mu.Unlock()

	if !internet {
		return
	}

	// A destination on the guest's own segment is not ours to relay: we do not
	// serve it, and the tunnel would let whoever holds the peer's key answer
	// for it, which turns a VPN peer into a machine on the guest's LAN.
	if guestNet != nil && guestNet.Contains(flow.DstIP) {
		m.refused(flow, "the guest's own subnet")
		return
	}

	// The tunnel decides what has a route at all, but the policy still stands
	// in front of it: a VPN that routes 0.0.0.0/0 would otherwise carry a
	// guest to the reserved ranges, and a guest has no business reaching for
	// those.
	if block := policy.BlockedBy(flow.DstIP); block != "" {
		m.refused(flow, block)
		return
	}

	switch flow.Proto {
	case ethlink.ProtoTCP:
		if flow.SYN && !flow.ACK {
			m.ensureTCP(flow.DstIP, flow.DstPort, Target{Name: "internet"})
		}
	case ethlink.ProtoUDP:
		m.ensureUDP(flow.DstIP, flow.DstPort, Target{Name: "internet"})
	}
}

// refused counts and reports a destination the policy would not let through.
func (m *Manager) refused(flow ethlink.Flow, block string) {
	m.deny(flow.DstIP.String(), block, "port", flow.DstPort)
}

// noticedMax bounds how many refused destinations get a line of their own: the
// point is that an operator can ask "why can this guest not reach that" without
// turning on the debug log, not that a guest inventing destinations can fill it.
const noticedMax = 64

// deny counts one destination the gateway refused, and says why. Every refusal
// lands in the same `denied` counter, because the question asked of it is one
// question; the first refusal of a particular address is also said at the
// default verbosity, because a bare count in the stats line cannot answer it,
// and the rest are left to the debug log so a guest spraying datagrams cannot
// make the log unreadable.
func (m *Manager) deny(to, why string, attrs ...any) {
	m.mu.Lock()
	m.denied++
	first := false
	if m.noticed == nil {
		m.noticed = map[string]bool{}
	}
	if !m.noticed[to] && len(m.noticed) < noticedMax {
		m.noticed[to] = true
		first = true
	}
	m.mu.Unlock()

	args := append([]any{"to", to, "why", why}, attrs...)
	if first {
		m.log.Warn("internet: refused", args...)
		return
	}
	m.log.Debug("internet: refused", args...)
}
