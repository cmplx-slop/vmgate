package svc

import (
	"log/slog"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Limits is what an operator may set about the gateway's budgets. Everything
// else about them is fixed here, so that the relay loops, which read the caps
// without the lock, cannot be shown one number and then another. A zero field
// means the default.
type Limits struct {
	// RelayIdle is how long an on-demand relay may sit without a guest using
	// it before the reaper takes it away.
	RelayIdle time.Duration

	// MaxConns caps the translations running at once.
	MaxConns int

	// MaxPathsTotal bounds the datagram paths open across the whole gateway.
	// The per-relay limit does not speak for the host: relays times paths is
	// how many sockets a guest can hold open.
	MaxPathsTotal int
}

// The budgets the gateway runs with. They are the numbers the README's security
// notes quote, so they are named rather than written inline, and they are
// defaults a caller can raise but not sidestep.
const (
	defaultMaxRelays     = 2048
	defaultMaxConns      = 256
	defaultMaxPaths      = 32
	defaultMaxPathsTotal = 1024

	// defaultMaxEchoRelays caps the pings relayed at once, separately from the
	// relay table. A ping is the cheapest relay a guest can ask for: one frame,
	// no handshake, and the source address is the guest's to invent, so a guest
	// with a loop would otherwise fill the table with pings and leave the next
	// guest unable to open a connection.
	defaultMaxEchoRelays = 128

	defaultRelayIdle   = 60 * time.Second
	defaultUDPIdle     = 90 * time.Second
	defaultTCPKeep     = 30 * time.Second
	defaultDialTimeout = 15 * time.Second
)

// NewManager returns a manager attached to stk, with the budgets an operator
// chose filled in with the defaults.
func NewManager(stk *stack.Stack, nic tcpip.NICID, dialer Dialer, log *slog.Logger, limits Limits, frames frameWriter) *Manager {
	if dialer == nil {
		dialer = NetDialer{}
	}
	if log == nil {
		log = slog.Default()
	}
	if limits.RelayIdle <= 0 {
		limits.RelayIdle = defaultRelayIdle
	}
	if limits.MaxConns <= 0 {
		limits.MaxConns = defaultMaxConns
	}
	if limits.MaxPathsTotal <= 0 {
		limits.MaxPathsTotal = defaultMaxPathsTotal
	}
	out := &Manager{
		stk:           stk,
		nic:           nic,
		dialer:        dialer,
		log:           log,
		udpIdle:       defaultUDPIdle,
		relayIdle:     limits.RelayIdle,
		tcpKeep:       defaultTCPKeep,
		dialTimeout:   defaultDialTimeout,
		services:      map[key]bool{},
		relays:        map[key]*relay{},
		own:           map[string]bool{},
		liveConns:     map[net.Conn]struct{}{},
		maxRelays:     defaultMaxRelays,
		maxEchoRelays: defaultMaxEchoRelays,
		maxConns:      limits.MaxConns,
		maxPaths:      defaultMaxPaths,
		maxPathsTotal: limits.MaxPathsTotal,
		frames:        frames,
	}
	return out
}
