package svc

import (
	"net"
	"time"
)

// Stop marks the manager as shutting down and closes the relays and
// translations that were open: a manager that has stopped holds nothing,
// whatever the stack underneath it does next.
func (m *Manager) Stop() {
	m.mu.Lock()
	m.stopped = true
	m.mu.Unlock()

	// Stopping means the relay goroutines have to finish, and they finish when
	// what they are reading is closed. Closing the stack behind them would do
	// it too, but only by accident of the order engine.Close happens to run in,
	// and a manager that has stopped should hold nothing on its own.
	m.closeEverything()
}

// stoppedLocked reports whether the manager is shutting down. Like everything
// with a Locked suffix, it expects m.mu to be held already.
func (m *Manager) stoppedLocked() bool { return m.stopped }

// Own marks an address as ours, so no on-demand relay is ever created for it.
func (m *Manager) Own(ip net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.own[ip.String()] = true
}

func (m *Manager) isStopped() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped
}

// release gives back the relay slot held by r. The identity check matters: a
// relay the reaper already replaced must not be freed by the listener loop that
// is still winding down.
func (m *Manager) release(k key, r *relay) {
	if r == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unclaimLocked(k, r)
}

// touch records that a guest used this relay, which is what keeps it out of
// the reaper.
func (m *Manager) touch(k key, r *relay) {
	m.mu.Lock()
	if m.relays[k] == r {
		r.last = time.Now()
	}
	m.mu.Unlock()
}

// addConn takes room in the translation budget and remembers the connection,
// which is what makes it possible to end a guest's translations when the guest
// itself goes away. False means the budget is full, and the second result is
// the cap that stopped it: a caller names it in a log line it prints after
// letting go of the lock, so the number has to come from here.
func (m *Manager) addConn(c net.Conn) (bool, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.liveConns) >= m.maxConns {
		return false, m.maxConns
	}
	m.liveConns[c] = struct{}{}
	return true, m.maxConns
}

func (m *Manager) dropConn(c net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.liveConns, c)
}

// Relays reports how many on-demand relays are currently installed, which is
// also how many slots of the relay budget are taken.
func (m *Manager) Relays() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.relays)
}

// pingsInFlight reports how many pings are being relayed right now, which is the
// number the ping ceiling is measured against: a table with room in it can still
// be full of pings.
func (m *Manager) pingsInFlight() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.echoRelays
}

// Conns reports how many translations are running.
func (m *Manager) Conns() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.liveConns)
}

// Paths reports how many datagram paths are open across the gateway.
func (m *Manager) Paths() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.openPaths
}

// takePath claims one datagram path out of the gateway's budget, and reports
// whether there was room. The per-relay limit is not enough on its own: relays
// times paths is what the host actually pays for.
func (m *Manager) takePath() bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.openPaths >= m.maxPathsTotal {
		return false
	}
	m.openPaths++
	return true
}

// releasePath gives the slot back when a path closes.
func (m *Manager) releasePath() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.openPaths > 0 {
		m.openPaths--
	}
}

// Denied reports how many guest destinations were refused: by the egress
// policy, by the tunnel having no route for them, by being inside the guest's
// own segment, or by the frame itself not adding up. It is one number because
// the question asked of it is one question: why can this guest not reach that.
func (m *Manager) Denied() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.denied
}

func mkKey(proto string, ip net.IP, port uint16) key {
	return key{proto: proto, ip: ip.String(), port: port}
}

// The protocol part of a relay key. The relay loops pass these; the ICMP one is
// named so that the ping counter below can recognise its own.
const (
	protoTCP  = "tcp"
	protoUDP  = "udp"
	protoEcho = "icmp"
)

// unclaimLocked takes one relay out of the table and gives back what it was
// holding in the per-protocol counters. Called with m.mu held, and only by the
// three places that end a relay: the loop that was running it, the reaper, and
// the session ending.
func (m *Manager) unclaimLocked(k key, r *relay) {
	if m.relays[k] != r {
		return
	}
	delete(m.relays, k)
	if k.proto == protoEcho && m.echoRelays > 0 {
		m.echoRelays--
	}
}
