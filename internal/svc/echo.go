package svc

import (
	"net"
	"time"

	"github.com/cmplx-slop/vmgate/internal/ethlink"
	"github.com/cmplx-slop/vmgate/internal/nsnet"
)

// frameWriter sends a frame the gateway built itself out to the guest. The link
// endpoint is one, and the ICMP answers below travel that way rather than
// through the stack, for the reason given on Manager.echo.
type frameWriter interface {
	WriteFrame(fr []byte) error
}

// The identifier, in one place, because it changes hands twice.
//
// The guest's identifier arrives in the frame and is what the answer has to
// carry back; it is one guest's invention, so it is only unique together with
// that guest's address, which is why both are in the relay's key. The path's
// identifier is the stack's, chosen when the socket was opened, and is what
// leaves through the tunnel and what an arriving answer is matched by. answered
// swaps one for the other on the way out, and the stack demuxes on its own
// before Answer is called; nsnet.Echo documents the socket side.
//
// EchoPath is one ICMP echo path out of the gateway: what is written along it
// leaves as an echo request to the address that was dialled, and what is read
// back is the answer to that request and nobody else's. The tunnel implements it
// inside the stack, so the tunnel's routes decide what can be reached, and an
// address outside the peer's AllowedIPs is turned down by the dial itself.
type EchoPath interface {
	Send(seq uint16, payload []byte) error
	Answer(buf []byte) (seq uint16, payload []byte, err error)
	Close() error

	// Ident is the identifier this path uses on the wire. It is the gateway's
	// own, chosen by the stack when the path was opened, and never the guest's:
	// the guest's identifier is put back on the way out. Worth a log line when a
	// relay is opened, because it is what an answer coming back is matched to.
	Ident() uint16
}

// answerBuf is the scratch an answer is read into. A ping is answered with what
// it asked for, and the request arrived in one frame, so nothing realistic is
// longer than this; an answer that is somehow longer is truncated.
const answerBuf = 2048

// echo handles an ICMP echo request from the guest.
//
// The gateway answers these itself, at the frame level, rather than leaving them
// to the stack, and that is worth a paragraph because it looks like duplication.
// The netstack has an IPv4 echo responder built into its network layer; it is
// always on and cannot be switched off. On the guest interface, which is in
// promiscuous mode so that relays can bind the addresses the guest dialled, that
// responder accepts an echo request for *any* address and answers it, spoofed
// from the address that was pinged. So a guest that pings 203.0.113.9 is told it
// answers, whether or not the tunnel carries that address at all: a reachability
// lie, and the exact destination policy the rest of this file enforces. Echo
// therefore never reaches the network layer on the guest side; the gateway
// answers what it means to answer and refuses the rest.
//
// Traffic in the other direction, a VPN peer pinging the gateway's tunnel
// address, is left to the responder: on the tunnel interface there is no
// promiscuous mode, so it only answers addresses the gateway really owns.
func (m *Manager) echo(req ethlink.Echo) {
	m.mu.Lock()
	own := m.own[req.DstIP.String()]
	internet := m.internet
	policy := m.policy
	guestNet := m.guestNet
	m.mu.Unlock()

	if req.Type != ethlink.TypeEcho {
		// An answer the guest is sending, to a ping someone else asked for.
		// There is no translation to carry it back through, so it goes no
		// further than here.
		m.log.Debug("icmp: echo answer from guest", "from", req.SrcIP, "to", req.DstIP)
		return
	}
	if m.frames == nil {
		m.log.Debug("icmp: nowhere to answer", "to", req.DstIP)
		return
	}
	if !req.ChecksumOK {
		// The frame does not add up. This gateway is the receiver for echo
		// frames, because it takes them away from the stack, and a receiver that
		// answers a corrupt message is worse than one that drops it: the reply
		// looks like an answer to a ping that was never really sent, and relaying
		// it would put the guest's payload on the tunnel unexamined.
		m.deny(req.DstIP.String(), "a checksum that does not add up",
			"proto", "icmp", "ident", req.Ident)
		return
	}

	// A ping to a broadcast address has no single address to answer from, and
	// the gateway is not a LAN full of hosts that all reply. Both the limited
	// broadcast and the guest segment's directed broadcast are checked here,
	// before the addresses we own, because the engine claims both so that
	// neither looks like a destination worth relaying. Answering a ping out of
	// one of them would be its own kind of lie: the guest would learn the
	// gateway's hardware address under a broadcast address and keep looking for
	// a host there.
	if req.DstIP.IsMulticast() || net.IPv4bcast.Equal(req.DstIP) ||
		(guestNet != nil && req.DstIP.Equal(subnetBroadcast(guestNet))) {
		m.deny(req.DstIP.String(), "not one machine's address", "proto", "icmp", "ident", req.Ident)
		return
	}

	// The gateway's own addresses, which include the tunnel's: a guest pinging
	// the address the VPN carries is pinging this process.
	if own {
		// Counted only once the answer has been accepted for the guest: an
		// answer to a guest that is not reading is not a service delivered, and
		// the counter is what an operator reads to decide whether ping works.
		if err := m.writeEcho(req.Reverse()); err != nil {
			return
		}
		m.log.Debug("icmp: answered locally", "to", req.DstIP, "ident", req.Ident, "seq", req.Seq)
		m.countEcho(&m.echoAnswered)
		return
	}
	if !internet {
		m.log.Debug("icmp: no internet", "to", req.DstIP)
		return
	}
	// The same guard the TCP and UDP relays use: an address on the guest's own
	// segment is not ours to answer for.
	if guestNet != nil && guestNet.Contains(req.DstIP) {
		m.deny(req.DstIP.String(), "the guest's own subnet", "proto", "icmp", "ident", req.Ident)
		return
	}
	if block := policy.BlockedBy(req.DstIP); block != "" {
		m.deny(req.DstIP.String(), block, "proto", "icmp", "ident", req.Ident)
		return
	}
	m.relayEcho(req)
}

// writeEcho sends one echo to the guest, exactly as described: it is up to the
// caller to have swapped the addresses and set the type. The error says whether
// the frame was accepted for the guest at all, which is what the counters key on.
func (m *Manager) writeEcho(e ethlink.Echo) error {
	if err := m.frames.WriteFrame(ethlink.EchoFrame(e)); err != nil {
		m.log.Debug("icmp: answer not sent", "to", e.DstIP, "err", err)
		return err
	}
	return nil
}

// answered is the answer to one request: addresses and MACs swapped, the
// identifier kept, and the sequence number and data the far side sent back put
// in place of the ones that went out. The far side answers with the identifier
// of the socket it was dialled with, which is the gateway's and not the guest's,
// so the guest has to be given its own back.
//
// The payload is not copied: it is the read buffer of the path, which the next
// read overwrites. writeEcho turns the answer into a frame immediately, and
// nothing else holds one of these.
func answered(req ethlink.Echo, seq uint16, payload []byte) ethlink.Echo {
	ans := req.Reverse()
	ans.Seq = seq
	ans.Payload = payload
	return ans
}

// relayEcho finds, or opens, the echo path for this request and sends it. The
// relay is keyed by requester, destination and identifier: two pings of one
// guest to one host share a path out, and two guests that picked the same
// identifier, which they will, do not. Without the requester in the key the
// second guest's answers would be written to the first one's address.
func (m *Manager) relayEcho(req ethlink.Echo) {
	k := mkKey(protoEcho, req.DstIP, req.Ident)
	k.src = req.SrcIP.String()

	path := m.existingEcho(k)
	if path == nil {
		path = m.openEcho(k, req)
		if path == nil {
			return
		}
	}
	// Counted after the send: a request that never left has not been relayed,
	// and saying otherwise is how a stats line turns into a wrong answer.
	if err := path.Send(req.Seq, req.Payload); err != nil {
		m.log.Debug("icmp: request failed", "to", req.DstIP, "err", err)
		return
	}
	m.countEcho(&m.echoRelayed)
}

// existingEcho is the path already open for this key, touched so that it stays
// out of the reaper, or nil if there is none.
func (m *Manager) existingEcho(k key) EchoPath {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.relays[k]; r != nil {
		r.last = time.Now()
		return r.echo
	}
	return nil
}

// openEcho dials one echo path through the tunnel and starts the loop that
// carries answers back. The path goes into the relay table with its closer
// already set, so the reaper can never find a relay it cannot tear down.
func (m *Manager) openEcho(k key, req ethlink.Echo) EchoPath {
	m.sweepRelays()

	m.mu.Lock()
	stopped := m.stoppedLocked()
	full, live, limit := len(m.relays) >= m.maxRelays, len(m.relays), m.maxRelays
	fullEcho, echoLimit := m.echoRelays >= m.maxEchoRelays, m.maxEchoRelays
	tunnel := m.tunnel
	m.mu.Unlock()

	switch {
	case stopped:
		return nil
	case full:
		m.log.Debug("icmp: too many relays", "relays", live, "limit", limit)
		return nil
	case fullEcho:
		// Said quietly and not counted as a refusal: this is not a destination the
		// policy objects to, it is this guest asking for more pings than the
		// gateway will carry alongside everybody else's connections.
		m.log.Debug("icmp: too many pings in flight", "to", req.DstIP, "limit", echoLimit)
		return nil
	case tunnel == nil:
		m.deny(req.DstIP.String(), "no tunnel to dial through", "proto", "icmp")
		return nil
	}

	path, err := tunnel.DialEcho(req.DstIP.String())
	if err != nil {
		m.refusedDial("icmp", req.DstIP.String(), err)
		return nil
	}

	r := &relay{last: time.Now(), closer: path, echo: path, asked: req}
	m.mu.Lock()
	if m.stoppedLocked() || m.relays[k] != nil || len(m.relays) >= m.maxRelays ||
		m.echoRelays >= m.maxEchoRelays {
		m.mu.Unlock()
		_ = path.Close()
		return nil
	}
	m.relays[k] = r
	m.echoRelays++
	m.mu.Unlock()

	// The identifier on the wire is the socket's, not the guest's: naming it
	// here is what makes an answer that came back for somebody else's ping
	// traceable.
	m.log.Debug("icmp: relay", "addr", k, "from", req.SrcIP, "socket_ident", path.Ident())
	go m.pumpEcho(k, r, path)
	return path
}

// pumpEcho carries answers back to the guest until the path dies, the relay is
// taken away, or the gateway stops. The guest is named by the request that
// opened the relay, and the relay's key names that guest, so an answer cannot be
// steered to a different machine: the addresses are copied from a frame the guest
// itself sent, a second guest that picked the same identifier opens its own path,
// and the identifier and sequence come from the answer the tunnel delivered.
func (m *Manager) pumpEcho(k key, r *relay, path EchoPath) {
	defer nsnet.Guard(m.log, "icmp relay")
	defer func() {
		_ = path.Close()
		m.release(k, r)
	}()

	buf := make([]byte, answerBuf)
	for {
		seq, payload, err := path.Answer(buf)
		if err != nil {
			if !m.isStopped() {
				m.log.Debug("icmp: path closed", "addr", k, "err", err)
			}
			return
		}
		m.touch(k, r)
		m.writeEcho(answered(r.asked, seq, payload))
	}
}

// countEcho adds one to a counter, which is the same lock the other counters
// use: these are read by the stats line, not on the frame path.
func (m *Manager) countEcho(field *int) {
	m.mu.Lock()
	*field++
	m.mu.Unlock()
}

// EchoAnswered counts the echo requests the gateway answered for itself.
func (m *Manager) EchoAnswered() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.echoAnswered
}

// EchoRelayed counts the echo requests sent on through the tunnel.
func (m *Manager) EchoRelayed() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.echoRelayed
}
