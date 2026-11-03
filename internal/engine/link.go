package engine

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"

	"vmgate/internal/nsnet"
	"vmgate/internal/qemu"
)

// inspect watches every inbound frame before the stack sees it, so on-demand
// relays exist before the SYN that asks for them is delivered, and so that the
// gateway can answer an ICMP echo itself. -sniff is handled by the netstack's
// own sniffer, which sees both directions: a frame taken here, and an answer
// written straight back to the guest, do not appear in it.
func (e *Engine) inspect(fr []byte) bool {
	return e.svcm.Inspect(fr)
}

// Attach makes c the link's frame transport without starting the read loop.
// ServeFrame attaches as well, but Attach lets a caller be sure the link is
// wired up before it starts handing sockets to either side: without it, a dial
// that arrives the instant after startup can reach a host listener while the
// link is still missing, and the dial into the guest fails.
func (e *Engine) Attach(c qemu.Conn) {
	e.link.SetConn(c)
}

// Serve takes one QEMU connection and pumps frames through the stack until the
// guest disconnects. It is meant to be called in a loop, so a guest reboot or
// a QEMU restart simply reconnects.
func (e *Engine) Serve(c net.Conn) error {
	return e.ServeFrame(qemu.NewStream(c))
}

// ServeFrame is Serve over an already delimited transport, which is how tests
// attach an in-process guest instead of QEMU.
//
// One session at a time, and saying so rather than sharing the link: the
// endpoint has a single transport, so a second session would replace the first
// one's, and the first one's exit would then clear the relays the second one is
// still using. The command accepts one QEMU connection at a time, so refusing
// here only turns a mistake into an error.
func (e *Engine) ServeFrame(c qemu.Conn) error {
	// Every frame is written by the guest, so the read loop is guarded the same
	// way the relays are: a panic ends this session, whose defers below close
	// the link and clear the guest's state, and does not end the process.
	defer nsnet.Guard(e.log, "link session")

	e.mu.Lock()
	if e.serving > 0 {
		e.mu.Unlock()
		_ = c.Close()
		return fmt.Errorf("engine: link session %d is still running, refusing another", e.serving)
	}
	e.link.SetConn(c)
	e.serving++
	n := e.serving
	e.mu.Unlock()
	e.log.Info("link: connected", "session", n)

	err := e.link.Run()

	e.mu.Lock()
	e.serving--
	e.mu.Unlock()

	e.link.SetConn(nil)
	_ = c.Close()

	// Whatever relays and translations this guest had are its own: drop them
	// so the next session, or the same guest after a reboot, starts clean.
	e.svcm.EndSession()
	if err != nil {
		e.log.Info("link: disconnected", "session", n, "err", err)
		return err
	}
	e.log.Info("link: disconnected", "session", n)
	return nil
}

// Stats snapshots counters for logging.
func (e *Engine) Stats() Stats {
	st := Stats{
		Link:         e.link.Stats(),
		Relays:       e.svcm.Relays(),
		Conns:        e.svcm.Conns(),
		Paths:        e.svcm.Paths(),
		Denied:       e.svcm.Denied(),
		EchoAnswered: e.svcm.EchoAnswered(),
		EchoRelayed:  e.svcm.EchoRelayed(),
	}
	if e.dhcpSrv != nil {
		st.Leases = e.dhcpSrv.Leases()
	}
	if e.forward != nil {
		st.HostBridges = e.forward.Bridges()
		st.HostRefused = e.forward.BridgesRefused()
	}
	if e.tunnel != nil {
		st.VPN = e.tunnel.Peer()
	}
	return st
}

// Serving reports how many link sessions are running. A test uses it to wait
// for one session to end before joining the next.
func (e *Engine) Serving() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.serving
}

// StackStats returns the netstack's counters, which answer the question the
// link level counters cannot: what the stack did with the packets it saw.
func (e *Engine) StackStats() tcpip.Stats {
	return e.stk.Stats()
}
