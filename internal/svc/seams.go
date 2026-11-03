package svc

import (
	"context"
	"errors"
	"net"
)

// ErrStopped is returned when the manager is shutting down.
var ErrStopped = errors.New("svc: manager stopped")

// Dialer opens host side sockets. Tests swap in a dialer that maps arbitrary
// destinations onto local test servers.
//
// This is only ever used for endpoints the operator named: the [[service]]
// entries. A destination the guest chose is never dialled by the host; see
// Egress.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	ListenPacket(network, address string) (net.PacketConn, error)
}

// Egress reaches the network beyond the gateway on a guest's behalf. The VPN
// tunnel implements it: the dial is made from inside the stack on the tunnel's
// interface, so the tunnel's routes decide what can be reached, and answers can
// only come from the peer that was dialled.
type Egress interface {
	// DialTCP connects to a numeric "1.2.3.4:5678" address. ctx bounds the
	// attempt: an address that exists and says nothing must not hold a
	// translation forever.
	DialTCP(ctx context.Context, address string) (net.Conn, error)

	// DialUDP connects a datagram socket to one peer. The connect is itself a
	// route lookup, so an unroutable destination fails here, and only that
	// peer's datagrams are delivered back.
	DialUDP(address string) (Datagram, error)

	// DialEcho connects an ICMP echo socket to one address, so that a guest's
	// ping is answered by the host it pinged rather than by this process. The
	// address is numeric, as with the others: the guest chose it.
	DialEcho(address string) (EchoPath, error)
}

// Datagram is a connected datagram path: what is written goes to the peer that
// was dialled, and what is read is an answer from that peer and nobody else.
// Both a tunnel socket and a host socket are one, which is why this says
// nothing about where the bytes came from: the relay has to be able to hold a
// path out that it can also stand in front of in a test.
type Datagram interface {
	Write(p []byte) (int, error)
	Read(p []byte) (int, error)
	Close() error
}

// NetDialer uses the host kernel, which is what keeps the operator's own
// forwards rootless: no raw socket, only connections the host made on the
// gateway's behalf.
type NetDialer struct{}

// Dial implements Dialer.
func (NetDialer) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

// ListenPacket implements Dialer.
func (NetDialer) ListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

// Target describes where the far side of a translated connection lives.
type Target struct {
	// Addr is a host "host:port" to dial, chosen by the operator. When empty,
	// the original destination address of the guest connection is used, and
	// that destination is reached through the tunnel: this is what the
	// on-demand relays for a guest's own traffic do.
	Addr string

	// Name shows up in the log.
	Name string
}

// ViaHost reports whether the operator named a host endpoint, rather than the
// destination the guest asked for. The two are reached by different routes, and
// this is the only place that decides which is which: an empty string read
// inline in three functions is how that decision drifts.
func (t Target) ViaHost() bool { return t.Addr != "" }

// QueryHandler answers one datagram with one reply, which is how the DNS
// server is attached to the stack.
type QueryHandler func(msg []byte) ([]byte, error)
