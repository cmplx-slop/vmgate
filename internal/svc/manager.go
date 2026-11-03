package svc

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"vmgate/internal/config"
	"vmgate/internal/ethlink"
)

// Package svc runs the guest facing side of the translation: listeners inside
// the netstack that turn a guest's connection into something further out.
//
// Three kinds exist:
//
//   - Explicit services, configured with [[service]], bound to one of our own
//     addresses (the gateway or the DNS address) and forwarding to a fixed host
//     endpoint. This is how "guest connects to gateway:80" reaches an HTTP
//     server on the host.
//
//   - On-demand relays, created when a guest reaches for an address of its own:
//     when a frame arrives for an address nothing is listening for yet, a
//     listener is created for that exact (address, port) just before the frame
//     is delivered to the stack, so the very first SYN of a flow is not lost.
//     These are the only listeners a guest can cause, which makes them where
//     the guardrails live: the egress policy decides whether a destination gets
//     one at all, the idle reaper and EndSession take them away again, and the
//     connection and path caps bound how much state one guest can hold. What
//     they reach is the VPN tunnel, from inside the stack and pinned to its
//     interface, so the peer's AllowedIPs are the outer edge of what a guest can
//     touch and the host's own connection is never used for a guest's choice.
//
//   - DNS, a listener on our resolver addresses that answers from the dns
//     package rather than splicing to a fixed host endpoint.

type key struct {
	proto string
	ip    string
	port  uint16

	// src names who asked, and is set only for the ICMP relays. For TCP and UDP
	// the destination is the whole identity, because the transport sorts out the
	// conversations below the listener; an ICMP identifier is no such thing. It
	// is one guest's invention, freely chosen, so two guests that pick the same
	// one to ping the same host have to get their own path each.
	src string
}

func (k key) String() string {
	s := k.proto + " " + k.ip + ":" + strconv.Itoa(int(k.port))
	if k.src != "" {
		s += " from " + k.src
	}
	return s
}

// Manager owns the guest facing listeners.
type Manager struct {
	stk *stack.Stack

	// nic is the interface facing QEMU. Every listener here is bound to it,
	// and that pinning is not decoration: a peer's AllowedIPs are usually
	// 0.0.0.0/0, so a reply that was routed by the table alone would go into
	// the VPN, the DHCP broadcast included, and the guest would never get the
	// address it has no address without.
	nic    tcpip.NICID
	log    *slog.Logger
	dialer Dialer

	// The timeouts and the budgets below are fixed when the manager is built
	// and read without the lock afterwards, which is why they have no setters:
	// a cap that moves under the relay loops reading it is a race that only
	// shows up under load. Limits carries the ones an operator may change.

	// udpIdle is how long a datagram path may sit without traffic before the
	// next path from the same guest takes its place: a guest that opened a path
	// and stopped using it should not hold a host socket for the rest of the
	// relay's life.
	udpIdle time.Duration

	// relayIdle is how long an on-demand relay may sit without a guest using
	// it before the next relay takes its place. Without that the relay table
	// only ever grows, and one guest can fill it permanently.
	relayIdle time.Duration

	// tcpKeep asks the host kernel to notice a peer that vanished without
	// saying so, so a splice cannot hold a socket and two goroutines forever.
	tcpKeep time.Duration

	// dialTimeout bounds how long a tunnel connection attempt may take. An
	// address inside the tunnel that exists and never answers would otherwise
	// hold a translation, and a slot in the connection budget, for as long as
	// the stack's own retransmission schedule runs.
	dialTimeout time.Duration

	// frames is how an answer the gateway wrote itself reaches the guest, which
	// is the link endpoint: an echo answer never goes through the stack, for
	// the reason on Manager.echo. Without it ICMP is refused. It sits above the
	// lock with the other things fixed at construction so that the echo path
	// can read it without one.
	frames frameWriter

	mu        sync.Mutex
	stopped   bool
	services  map[key]bool
	relays    map[key]*relay
	own       map[string]bool
	liveConns map[net.Conn]struct{}
	denied    int

	// echoRelays counts the pings being relayed right now. The table's cap says
	// how many relays there may be; this says how many of them may be pings, so
	// that ping cannot use the whole table up. See defaultMaxEchoRelays.
	echoRelays int

	// echoAnswered and echoRelayed split the pings the gateway handled into
	// the ones it answered itself and the ones it sent on through the tunnel,
	// which is the first question anyone asks when a ping does not come back.
	echoAnswered int
	echoRelayed  int

	// noticed remembers which refused destinations have already been said out
	// loud, so the count keeps adding up without the log doing so too.
	noticed map[string]bool

	// internet turns on-demand relaying of arbitrary destinations on.
	internet bool

	maxRelays int

	// maxEchoRelays caps how many of those relays may be pings: pings are the
	// cheapest thing a guest can fill the table with.
	maxEchoRelays int

	// maxConns caps the translations running at once, and maxPaths the far
	// side sockets one UDP relay may open: a guest can ask for both without
	// bound, and its source addresses are its own to invent.
	maxConns int
	maxPaths int

	// maxPathsTotal bounds the datagram paths open across the whole gateway.
	// maxPaths only speaks for one relay, and a guest that reaches many
	// destinations multiplies the two: relays times paths is tens of thousands
	// of host sockets, which is a denial of service against the host rather
	// than against the guest.
	maxPathsTotal int
	openPaths     int

	// policy decides which destinations an on-demand relay may dial at all.
	policy *config.EgressPolicy

	// guestNet is the network the guest itself is on. A destination inside it
	// is never relayed: nothing on that segment belongs to us, and the tunnel
	// would otherwise let whoever holds the peer's key answer for a machine on
	// the guest's own LAN.
	guestNet *net.IPNet

	// tunnel is how a destination the guest chose is reached. Without it,
	// relaying such a destination is refused: there is no fallback path onto
	// the host's own connection.
	tunnel Egress
}

// relay is one on-demand listener. It holds the endpoint so the reaper can
// take it away, and the time a guest last asked for it.
type relay struct {
	last   time.Time
	closer io.Closer

	// echo and asked belong to an ICMP relay: the path out through the tunnel,
	// and the request that opened it, which names the machine to answer and the
	// identifier to answer with. Answers only ever go back to that machine,
	// which the key now guarantees by carrying its address. The relays for TCP
	// and UDP leave these empty, and one table and one reaper covering every
	// protocol is worth that.
	echo  EchoPath
	asked ethlink.Echo
}
