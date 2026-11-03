package vpn

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tunShim is a wireguard tun.Device whose interface is a gVisor channel
// endpoint: what wireguard-go decrypts is injected into the netstack, and what
// the netstack routes to the tunnel is handed to wireguard-go. There is no TUN
// device, no file descriptor and no privilege anywhere in this.
//
// It also decides what may enter the stack from the far end of the tunnel. A
// VPN peer is only marginally less hostile than the guest: it can send any
// bytes it likes, so anything that is not a plain IPv4 packet of a sane length
// is counted and dropped rather than handed to the network layer.
type tunShim struct {
	ep  *channel.Endpoint
	mtu int

	// serves are the addresses the tunnel owns. An inner packet may only be
	// destined for one of them: shape alone is not a destination check, and a
	// peer that can address the gateway's listeners can exhaust the guest's
	// DHCP pool or shake hands with a relay a guest happened to open. mu guards
	// it because AddAddress can be called while the peer is already sending.
	mu     sync.Mutex
	serves []tcpip.Address

	// events stays empty: there is no link to go up or down, and wireguard-go
	// only reads this channel for interface events.
	events chan tun.Event

	// dropped counts what the shim refused from the peer because it was not a
	// packet at all, and misaimed counts the well-formed ones aimed at an
	// address the tunnel does not carry. Both are in the status line, because
	// the two look the same from the guest's side and mean different things:
	// one says the peer or the tunnel is broken, the other says the peer is
	// sending to somewhere it should not. oversize counts packets going the
	// other way that would not fit the tunnel, which is a mistake of ours.
	dropped  atomic.Uint64
	misaimed atomic.Uint64
	oversize atomic.Uint64
	closed   atomic.Bool
}

// errShimClosed is what Read returns once the tunnel is gone, which is what
// makes wireguard-go's reader routine stop.
var errShimClosed = errors.New("vpn: tunnel closed")

func newShim(ep *channel.Endpoint, mtu int, serves []tcpip.Address) *tunShim {
	return &tunShim{ep: ep, mtu: mtu, serves: serves, events: make(chan tun.Event, 1)}
}

// serve adds an address the tunnel has been given, so the shim will carry
// packets for it. It has to be the shim that knows, not just the stack: an
// interface that answers for an address the tunnel refuses to deliver is an
// address nobody can reach.
func (s *tunShim) serve(a tcpip.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, have := range s.serves {
		if have == a {
			return
		}
	}
	s.serves = append(s.serves, a)
}

// owns reports whether a destination is one the tunnel carries.
func (s *tunShim) owns(dst tcpip.Address) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, have := range s.serves {
		if have == dst {
			return true
		}
	}
	return false
}

// File returns nil: there is no descriptor to poll. wireguard-go reads Events()
// for interface events and nothing else, and its own userspace-only device does
// the same.
func (s *tunShim) File() *os.File { return nil }

func (s *tunShim) Name() (string, error) { return "vpn", nil }

func (s *tunShim) MTU() (int, error) { return s.mtu, nil }

// BatchSize is 1: one packet at a time, which is what a channel endpoint gives.
func (s *tunShim) BatchSize() int { return 1 }

func (s *tunShim) Events() <-chan tun.Event { return s.events }

func (s *tunShim) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.ep.Close()
	}
	return nil
}

// Read takes one packet the stack routed to the tunnel and copies it into
// wireguard-go's buffer at offset. It blocks until there is a packet or the
// tunnel closes.
//
// A packet that would not fit is dropped whole rather than chopped: a truncated
// packet is worse than a lost one, and an error here would end wireguard-go's
// reader routine, which is only meant to see one when the device is gone.
func (s *tunShim) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		pb := s.ep.ReadContext(context.Background())
		if pb == nil {
			return 0, errShimClosed
		}

		// The stack keeps headers and payload in separate regions of the same
		// buffer, so the packet is the concatenation of all of them.
		total := 0
		for _, seg := range pb.AsSlices() {
			total += len(seg)
		}
		if total > len(bufs[0])-offset {
			pb.DecRef()
			s.oversize.Add(1)
			continue
		}

		n := 0
		for _, seg := range pb.AsSlices() {
			n += copy(bufs[0][offset+n:], seg)
		}
		pb.DecRef()

		sizes[0] = n
		return 1, nil
	}
}

// Write takes one packet wireguard-go decrypted and puts it on the tunnel
// interface, or refuses it.
func (s *tunShim) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		pkt := b[offset:]
		// A packet that is not a packet and one that is aimed somewhere the
		// tunnel does not carry are counted apart: the two mean different
		// things to whoever reads the status line.
		ok, misaimed := s.acceptable(pkt)
		if !ok {
			if misaimed {
				s.misaimed.Add(1)
			} else {
				s.dropped.Add(1)
			}
			continue
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			// The tunnel's buffers are reused, so the stack has to own a copy.
			Payload: buffer.MakeWithData(append([]byte(nil), pkt...)),
		})
		s.ep.InjectInbound(header.IPv4ProtocolNumber, pb)
		pb.DecRef()
	}
	return len(bufs), nil
}

// acceptable is the one place bytes from the far end of the tunnel are judged.
// Only IPv4 is routed here, so IPv6, ARP or a truncated header never reaches
// the network layer, an oversized inner packet cannot be used to make the stack
// allocate for free, and the destination has to be an address the tunnel owns:
// shape alone would let a peer poke the gateway's own listeners, including the
// DHCP server, whose pool belongs to the guest.
//
// It reports whether the packet may go through and, when it may not, whether
// the reason was the destination rather than the packet: a peer that sends
// rubbish and a peer that sends to the wrong place are different problems, and
// counting them together hides both.
//
// The stack refuses a wrong destination today as well, because the tunnel
// interface is not promiscuous and its IPv4 layer drops a destination it does
// not own. That makes this a second line, and the one that still holds if the
// tunnel ever learns to accept what the route table hands it: it is not code to
// remove as redundant.
func (s *tunShim) acceptable(pkt []byte) (ok, misaimed bool) {
	if len(pkt) < header.IPv4MinimumSize {
		return false, false
	}
	if len(pkt) > s.mtu {
		return false, false
	}
	if pkt[0]>>4 != 4 {
		return false, false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < header.IPv4MinimumSize || ihl > len(pkt) {
		return false, false
	}
	total := int(header.IPv4(pkt).TotalLength())
	if total != len(pkt) {
		return false, false
	}

	dst := header.IPv4(pkt).DestinationAddress()
	if s.owns(dst) {
		return true, false
	}
	return false, true
}

// Dropped reports how many packets the shim refused from the peer because they
// were not well-formed IPv4.
func (s *tunShim) Dropped() uint64 { return s.dropped.Load() }

// Misaimed reports how many well-formed packets the peer sent to an address
// this tunnel does not carry.
func (s *tunShim) Misaimed() uint64 { return s.misaimed.Load() }

// Oversize reports how many packets going the other way were too large for the
// tunnel and were dropped rather than cut down.
func (s *tunShim) Oversize() uint64 { return s.oversize.Load() }
