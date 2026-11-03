// Package nsnet is the way a gVisor netstack is driven from Go code: address
// conversion, UDP and ping endpoints that block the way net.Conn does, the dial
// and listen helpers that pin a socket to one interface, and the splice that
// moves bytes between two endpoints.
//
// The pinning is not tidiness. A pinned socket's route lookup only considers
// that interface's routes, which is what makes a VPN peer's AllowedIPs the whole
// of a guest's reachability instead of one hint among several: see pin_test.go.
package nsnet

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// ErrClosed is returned by reads and writes on a closed endpoint.
var ErrClosed = errors.New("nsnet: endpoint closed")

// stackError adapts a netstack error to Go's error interface. The netstack's
// error type deliberately does not implement error, so it has to be wrapped
// before it can travel through ordinary Go code.
type stackError struct{ Err tcpip.Error }

// Error implements error.
func (e *stackError) Error() string { return e.Err.String() }

// stackErrorOf returns the netstack error behind err, or nil when err did not
// come from the stack. Callers switch on the concrete netstack type, for
// instance *tcpip.ErrWouldBlock.
func stackErrorOf(err error) tcpip.Error {
	var ne *stackError
	if errors.As(err, &ne) {
		return ne.Err
	}
	return nil
}

// ToError converts a netstack error, returning a nil error for a nil argument.
func ToError(err tcpip.Error) error {
	if err == nil {
		return nil
	}
	return &stackError{Err: err}
}

// AddrOf converts a net.IP into a netstack address. A nil IP becomes the
// wildcard address.
func AddrOf(ip net.IP) tcpip.Address {
	if ip == nil {
		return tcpip.Address{}
	}
	if v4 := ip.To4(); v4 != nil {
		return tcpip.AddrFrom4Slice(v4)
	}
	return tcpip.AddrFrom16Slice(ip.To16())
}

// ipOf converts a netstack address into a net.IP.
func ipOf(a tcpip.Address) net.IP {
	if a.BitLen() == 0 {
		return nil
	}
	return net.IP(a.AsSlice())
}

// Full builds a netstack socket address tied to a NIC.
func Full(nic tcpip.NICID, ip net.IP, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nic, Addr: AddrOf(ip), Port: port}
}

// UDP is a gVisor UDP endpoint with a blocking Read and a WriteTo that is
// allowed to send broadcasts. It satisfies dhcp.Conn.
type UDP struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	nic    tcpip.NICID
	mu     sync.Mutex
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once

	local *net.UDPAddr

	// pinPeer records that the endpoint is connected to one peer, so writes
	// go to it without naming an address again.
	pinPeer bool
}

// ListenUDP binds a UDP endpoint on ip:port. A nil ip binds the wildcard
// address; port 0 asks the stack for a free port.
func ListenUDP(stk *stack.Stack, nic tcpip.NICID, ip net.IP, port uint16) (*UDP, error) {
	wq := &waiter.Queue{}
	ep, terr := stk.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, wq)
	if terr != nil {
		return nil, ToError(terr)
	}
	// The DHCP reply and the broadcast helpers need to reach 255.255.255.255.
	ep.SocketOptions().SetBroadcast(true)

	if terr := ep.Bind(Full(nic, ip, port)); terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	local, terr := ep.GetLocalAddress()
	if terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	return &UDP{
		ep:    ep,
		wq:    wq,
		nic:   nic,
		done:  make(chan struct{}),
		local: &net.UDPAddr{IP: ipOf(local.Addr), Port: int(local.Port)},
	}, nil
}

// DialUDP connects a UDP endpoint to one peer through nic.
//
// Connecting matters for more than typing: the connect is a route lookup on
// that interface, so a destination nic has no route for fails here instead of
// sending a datagram somewhere unexpected, and once connected only that peer's
// datagrams are delivered. A relay that merely bound a port and wrote onwards
// would let any host on the internet inject replies into a guest's flow.
func DialUDP(stk *stack.Stack, nic tcpip.NICID, ip net.IP, port uint16) (*UDP, error) {
	wq := &waiter.Queue{}
	ep, terr := stk.NewEndpoint(udp.ProtocolNumber, header.IPv4ProtocolNumber, wq)
	if terr != nil {
		return nil, ToError(terr)
	}

	// Bind the wildcard address of that interface, so the source address comes
	// from its route lookup: on a tunnel that is the tunnel's own address, and
	// nothing else.
	local := Full(nic, nil, 0)
	if terr := ep.Bind(local); terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	if terr := ep.Connect(Full(nic, ip, port)); terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	local, terr = ep.GetLocalAddress()
	if terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	return &UDP{
		ep:      ep,
		wq:      wq,
		nic:     nic,
		done:    make(chan struct{}),
		local:   &net.UDPAddr{IP: ipOf(local.Addr), Port: int(local.Port)},
		pinPeer: true,
	}, nil
}

// LocalAddr reports the address the endpoint is bound to.
func (u *UDP) LocalAddr() *net.UDPAddr { return u.local }

// Read returns the next datagram, copied into p, plus its source address.
// Datagrams longer than p are truncated.
func (u *UDP) Read(p []byte) (int, *net.UDPAddr, error) {
	for {
		if u.closed.Load() {
			return 0, nil, ErrClosed
		}
		w := sliceWriter(p)
		res, terr := u.ep.Read(&w, tcpip.ReadOptions{NeedRemoteAddr: true})
		switch terr.(type) {
		case nil:
			var from *net.UDPAddr
			if res.RemoteAddr.Addr.BitLen() != 0 {
				from = &net.UDPAddr{IP: ipOf(res.RemoteAddr.Addr), Port: int(res.RemoteAddr.Port)}
			}
			return res.Count, from, nil
		case *tcpip.ErrWouldBlock:
			if err := u.waitReadable(); err != nil {
				return 0, nil, err
			}
		case *tcpip.ErrClosedForReceive:
			return 0, nil, ErrClosed
		case *tcpip.ErrInvalidEndpointState:
			return 0, nil, ErrClosed
		default:
			return 0, nil, ToError(terr)
		}
	}
}

func (u *UDP) waitReadable() error {
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp)
	u.wq.EventRegister(&e)
	defer u.wq.EventUnregister(&e)
	select {
	case <-ch:
		return nil
	case <-u.done:
		return ErrClosed
	}
}

// WriteTo sends p to to. On a connected endpoint the peer is already known, so
// the address is not named again: a connected endpoint cannot be pointed at
// somewhere else.
func (u *UDP) WriteTo(p []byte, to *net.UDPAddr) (int, error) {
	if u.pinPeer {
		return u.Write(p)
	}
	if u.closed.Load() {
		return 0, ErrClosed
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	fa := tcpip.FullAddress{NIC: u.nic, Addr: AddrOf(to.IP), Port: uint16(to.Port)}
	n, terr := u.ep.Write(bytes.NewReader(p), tcpip.WriteOptions{To: &fa})
	if terr != nil {
		return 0, ToError(terr)
	}
	return int(n), nil
}

// Write sends p to the peer the endpoint is connected to.
func (u *UDP) Write(p []byte) (int, error) {
	if u.closed.Load() {
		return 0, ErrClosed
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	n, terr := u.ep.Write(bytes.NewReader(p), tcpip.WriteOptions{})
	if terr != nil {
		return 0, ToError(terr)
	}
	return int(n), nil
}

// Close closes the endpoint and unblocks readers.
func (u *UDP) Close() error {
	u.once.Do(func() {
		u.closed.Store(true)
		close(u.done)
		u.ep.Close()
	})
	return nil
}

// sliceWriter lets the netstack read API copy straight into a caller buffer.
type sliceWriter []byte

// Write copies what fits. Saying so when it did not fit is not a detail: the
// stack insists a Writer that returns no error took everything, and panics
// otherwise ("io.Writer.Write succeeded with incomplete write",
// stack/packet_buffer.go). A datagram longer than the caller's buffer is the
// normal way to get there, from a guest or from the VPN peer, so this is the
// line that keeps one oversized packet from ending the process.
func (w *sliceWriter) Write(p []byte) (int, error) {
	n := copy(*w, p)
	*w = (*w)[n:]
	if n < len(p) {
		return n, io.ErrShortWrite
	}
	return n, nil
}
