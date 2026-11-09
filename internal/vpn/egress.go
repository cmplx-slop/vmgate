package vpn

import (
	"context"
	"net"

	"github.com/cmplx-slop/vmgate/internal/nsnet"
	"github.com/cmplx-slop/vmgate/internal/svc"
)

// DialTCP connects to "1.2.3.4:5678" through the tunnel.
//
// A destination outside the peer's AllowedIPs fails here, with a netstack error
// a caller can name: see nsnet.NoRoute.
func (t *Tunnel) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	stk, nic, err := t.path()
	if err != nil {
		return nil, err
	}
	ip, port, err := parseV4Port(addr)
	if err != nil {
		return nil, err
	}
	return nsnet.DialTCP(ctx, stk, nic, ip, port)
}

// DialUDP connects a datagram socket to one peer through the tunnel. Connecting
// is what makes the AllowedIPs rule hold for UDP as well: the connect is a
// route lookup, and it only delivers that peer's answers.
func (t *Tunnel) DialUDP(addr string) (svc.Datagram, error) {
	u, err := t.dialUDP(addr)
	if err != nil {
		return nil, err
	}
	return tunnelConn{u}, nil
}

// DialEcho connects an ICMP echo socket to one address through the tunnel. This
// is how a guest's ping leaves this process: the tunnel's routes say whether the
// address can be reached at all, the stack gives the socket an identifier of its
// own, and only answers carrying it are delivered.
func (t *Tunnel) DialEcho(addr string) (svc.EchoPath, error) {
	stk, nic, err := t.path()
	if err != nil {
		return nil, err
	}
	ip, err := parseV4(addr)
	if err != nil {
		return nil, err
	}
	p, err := nsnet.DialEcho(stk, nic, ip)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// dialUDP is the same socket before it is seen as a datagram path: the resolver
// reads it with the netstack's own three result Read, to see who answered.
func (t *Tunnel) dialUDP(addr string) (*nsnet.UDP, error) {
	stk, nic, err := t.path()
	if err != nil {
		return nil, err
	}
	ip, port, err := parseV4Port(addr)
	if err != nil {
		return nil, err
	}
	return nsnet.DialUDP(stk, nic, ip, port)
}

// tunnelConn is a connected socket inside the stack, seen as a datagram path.
// The connect fixed the route and the peer at the same time, so Read only ever
// sees an answer from the destination that was dialled.
type tunnelConn struct{ u *nsnet.UDP }

func (c tunnelConn) Write(b []byte) (int, error) { return c.u.Write(b) }

func (c tunnelConn) Read(b []byte) (int, error) {
	n, _, err := c.u.Read(b)
	return n, err
}

func (c tunnelConn) Close() error { return c.u.Close() }
