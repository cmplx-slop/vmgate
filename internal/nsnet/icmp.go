package nsnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// The answer a ping gets back is not something this gateway expects to argue
// with, so the two ways it can be wrong are reported plainly.
var (
	// ErrShortMessage is a reply too short to hold an ICMP header.
	ErrShortMessage = errors.New("nsnet: short icmp message")

	// ErrNotAnswer is a reply that is not an echo answer.
	ErrNotAnswer = errors.New("nsnet: not an icmp echo answer")
)

// Echo is an ICMP echo socket inside the stack: it sends echo requests towards
// one address and only ever reads the answers to those requests.
//
// The stack, not the caller, owns the identifier. Binding with port 0 leaves
// the stack to pick one from the ephemeral range, it stamps that identifier on
// every request written, and only answers carrying it are delivered. That is
// what makes one socket per conversation enough: there is no identifier to
// match up by hand, and a host that guesses a sequence number cannot inject an
// answer into someone else's ping.
type Echo struct {
	ep     tcpip.Endpoint
	wq     *waiter.Queue
	mu     sync.Mutex
	closed atomic.Bool
	done   chan struct{}
	once   sync.Once

	ident uint16
}

// DialEcho opens an echo socket towards dst through nic.
//
// As with DialUDP, the connect is a route lookup on that interface, so a
// destination the interface has no route for fails here rather than sending a
// request somewhere unexpected; on a WireGuard tunnel that is the point at
// which a destination outside the peer's AllowedIPs is turned down.
func DialEcho(stk *stack.Stack, nic tcpip.NICID, dst net.IP) (*Echo, error) {
	wq := &waiter.Queue{}
	ep, terr := stk.NewEndpoint(icmp.ProtocolNumber4, header.IPv4ProtocolNumber, wq)
	if terr != nil {
		return nil, ToError(terr)
	}
	if terr := ep.Bind(tcpip.FullAddress{NIC: nic}); terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	if terr := ep.Connect(Full(nic, dst, 0)); terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	local, terr := ep.GetLocalAddress()
	if terr != nil {
		ep.Close()
		return nil, ToError(terr)
	}
	return &Echo{
		ep:    ep,
		wq:    wq,
		done:  make(chan struct{}),
		ident: local.Port,
	}, nil
}

// Ident is the identifier the stack gave this socket, which is what an answer
// carries on the wire. It is worth a line in a log when pings go missing.
func (p *Echo) Ident() uint16 { return p.ident }

// Send writes one echo request. The identifier and the checksum are the
// stack's business, so only the sequence number and the data are given here.
func (p *Echo) Send(seq uint16, payload []byte) error {
	if p.closed.Load() {
		return ErrClosed
	}
	msg := make([]byte, header.ICMPv4MinimumSize+len(payload))
	msg[0] = byte(header.ICMPv4Echo)
	binary.BigEndian.PutUint16(msg[6:], seq)
	copy(msg[header.ICMPv4MinimumSize:], payload)

	p.mu.Lock()
	defer p.mu.Unlock()
	if _, terr := p.ep.Write(bytes.NewReader(msg), tcpip.WriteOptions{}); terr != nil {
		return ToError(terr)
	}
	return nil
}

// Answer reads the next echo answer, taking its data from buf, and reports the
// sequence number it carries. An answer longer than buf is truncated, which a
// gateway's own pings do not reach: an answer is no larger than the request it
// answers.
func (p *Echo) Answer(buf []byte) (seq uint16, payload []byte, err error) {
	for {
		if p.closed.Load() {
			return 0, nil, ErrClosed
		}
		w := sliceWriter(buf)
		res, terr := p.ep.Read(&w, tcpip.ReadOptions{})
		switch terr.(type) {
		case nil:
			if res.Count < header.ICMPv4MinimumSize {
				return 0, nil, ErrShortMessage
			}
			msg := buf[:res.Count]
			if msg[0] != byte(header.ICMPv4EchoReply) {
				return 0, nil, ErrNotAnswer
			}
			return binary.BigEndian.Uint16(msg[6:]), msg[header.ICMPv4MinimumSize:], nil
		case *tcpip.ErrWouldBlock:
			if err := p.waitReadable(); err != nil {
				return 0, nil, err
			}
		case *tcpip.ErrClosedForReceive, *tcpip.ErrInvalidEndpointState:
			return 0, nil, ErrClosed
		default:
			return 0, nil, ToError(terr)
		}
	}
}

// Close closes the socket and unblocks a reader.
func (p *Echo) Close() error {
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.done)
		p.ep.Close()
	})
	return nil
}

func (p *Echo) waitReadable() error {
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp)
	p.wq.EventRegister(&e)
	defer p.wq.EventUnregister(&e)
	select {
	case <-ch:
		return nil
	case <-p.done:
		return ErrClosed
	}
}
