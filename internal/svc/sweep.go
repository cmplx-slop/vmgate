package svc

import (
	"io"
	"net"
	"time"
)

// sweepRelays takes away the on-demand relays that no guest has used for
// relayIdle. They are recreated on the next frame, so the only cost is a
// listener that has to be opened twice in a rare case; the gain is that a guest
// cannot fill the table and leave it full.
//
// It runs where the relay table is written, not on a timer, because that is the
// moment an idle relay matters: a table full of relays nobody is using should
// make room for the one being asked for, not refuse it. Nothing else notices an
// idle relay, and the two places that end a guest's state - EndSession and Stop
// - close the lot anyway.
//
// m.mu is not held while the closers run. A panic in one of them is not caught
// here either: the caller is the link read loop or a relay loop, both already
// guarded, and the teardown that follows releases more than the sweep would
// have.
func (m *Manager) sweepRelays() {
	now := time.Now()
	var dead []io.Closer

	m.mu.Lock()
	for k, r := range m.relays {
		if now.Sub(r.last) > m.relayIdle {
			dead = append(dead, r.closer)
			m.unclaimLocked(k, r)
		}
	}
	m.mu.Unlock()

	for _, c := range dead {
		if c != nil {
			_ = c.Close()
		}
	}
}

// EndSession tears down everything the present guest caused: the on-demand
// relays and the translations running through them. The explicit services stay,
// because the operator asked for those.
//
// Closing the translations matters as much as closing the relays. A guest that
// vanishes mid-connection leaves its side of a splice in the netstack, where it
// sits retransmitting into a link that is gone: the copy loops never finish, the
// host socket is never returned, and a budget of connections that is never
// given back stops the next guest, or the same guest after a reboot, from
// translating anything at all.
func (m *Manager) EndSession() { m.closeEverything() }

// closeEverything empties the relay table and the translation list and closes
// what was in them. EndSession does it because a guest's state is its own, and
// Stop does it because a stopped manager should hold nothing.
func (m *Manager) closeEverything() {
	var dead []io.Closer
	var conns []net.Conn

	m.mu.Lock()
	for c := range m.liveConns {
		conns = append(conns, c)
	}
	m.liveConns = map[net.Conn]struct{}{}
	for k, r := range m.relays {
		dead = append(dead, r.closer)
		delete(m.relays, k)
	}
	m.relays = map[key]*relay{}
	m.echoRelays = 0
	m.mu.Unlock()

	for _, c := range dead {
		if c != nil {
			_ = c.Close()
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
