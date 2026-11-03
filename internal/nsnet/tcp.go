package nsnet

import (
	"context"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// NoRoute reports whether err is the stack refusing to send to a destination it
// has no route to. This is the answer a socket pinned to one interface gets for
// anything that interface has no route for, which on a VPN tunnel means a
// destination outside the peer's AllowedIPs.
func NoRoute(err error) bool {
	switch stackErrorOf(err).(type) {
	case *tcpip.ErrNetworkUnreachable, *tcpip.ErrHostUnreachable, *tcpip.ErrBadLocalAddress:
		return true
	}
	return false
}

// DialTCP connects a TCP endpoint to ip:port through nic and hands back a
// blocking net.Conn.
//
// Naming the nic is what makes this usable for a gateway: the route lookup is
// restricted to that interface, so a socket can only ever reach a destination
// that interface has a route to. On a VPN tunnel that is the peer's AllowedIPs,
// and anything else fails here with a netstack error the caller can name,
// rather than quietly going out some other way.
//
// The endpoint is always closed if the dial fails: a guest that aims
// connections at black holes must not leave one half-open endpoint each time.
func DialTCP(ctx context.Context, stk *stack.Stack, nic tcpip.NICID, ip net.IP, port uint16) (net.Conn, error) {
	wq := &waiter.Queue{}

	ep, terr := stk.NewEndpoint(tcp.ProtocolNumber, header.IPv4ProtocolNumber, wq)
	if terr != nil {
		return nil, ToError(terr)
	}

	// Connect is asynchronous: it reports ErrConnectStarted and the answer
	// arrives later, as writability for a good handshake or as LastError for
	// a bad one.
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents | waiter.EventErr)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	terr = ep.Connect(Full(nic, ip, port))
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ch:
			terr = ep.LastError()
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		}
	}

	if terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	return gonet.NewTCPConn(wq, ep), nil
}
