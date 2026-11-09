package ethlink

import (
	"errors"
	"io"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/cmplx-slop/vmgate/internal/qemu"
)

// WritePackets implements stack.LinkEndpoint.
//
// The frames are put on the transport here, on the goroutine that produced them,
// which is the honest place: the stack is told what really left. What that costs
// is bounded by the transport, whose own write gives up on a guest that has
// stopped taking frames; see the note on qemu.Conn.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	conn, closed, stalled := e.conn, e.closed, e.writeErr
	e.mu.RUnlock()
	if closed || conn == nil || stalled != nil {
		return 0, &tcpip.ErrAborted{}
	}

	written := 0
	for _, pkt := range pkts.AsSlice() {
		fr := padRunt(flatten(pkt))
		if err := conn.WriteFrame(fr); err != nil {
			e.stats.dropped.Add(1)
			e.noteWriteFailure(conn, err)
			if written > 0 {
				return written, nil
			}
			return 0, &tcpip.ErrAborted{}
		}
		e.stats.txFrames.Add(1)
		e.stats.txBytes.Add(uint64(pkt.Size() + header.EthernetMinimumSize))
		written++
	}
	return written, nil
}

// padRunt lengthens a frame to the shortest one the wire may carry. A real NIC
// does this on the way out, and a guest that sent a runt expects to be handed a
// legal qemu.
func padRunt(fr []byte) []byte {
	if len(fr) < qemu.MinFrameSize {
		return append(fr, make([]byte, qemu.MinFrameSize-len(fr))...)
	}
	return fr
}

// flatten copies a packet buffer, link header included, into one slice.
func flatten(pkt *stack.PacketBuffer) []byte {
	slices := pkt.AsSlices()
	n := 0
	for _, s := range slices {
		n += len(s)
	}
	out := make([]byte, 0, n)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

// Run reads frames from the endpoint's connection and delivers them to the
// stack until the connection fails, the endpoint is closed, or the connection
// is replaced. The engine calls it in a loop, once per QEMU connection.
func (e *Endpoint) Run() error {
	e.mu.RLock()
	conn, closed := e.conn, e.closed
	e.mu.RUnlock()
	if closed || conn == nil {
		return errors.New("ethlink: no connection")
	}

	for {
		fr, err := conn.ReadFrame()
		if err != nil {
			// A garbled frame is the guest's problem, not a reason to drop the
			// link; anything else means the transport is gone.
			if errors.Is(err, qemu.ErrBadLength) {
				e.stats.dropped.Add(1)
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			e.mu.RLock()
			isClosed := e.closed
			e.mu.RUnlock()
			if isClosed {
				return nil
			}
			e.stats.dropped.Add(1)

			// When it was a failed write that closed the transport, report the
			// write: the read side can only describe the close we caused.
			e.mu.RLock()
			stalled := e.writeErr
			e.mu.RUnlock()
			if stalled != nil {
				return stalled
			}
			return err
		}
		e.mu.RLock()
		inspect := e.inspect
		e.mu.RUnlock()
		if inspect != nil && !inspect(fr) {
			e.stats.held.Add(1)
			continue
		}
		e.deliver(fr)
	}
}

// deliver turns a raw frame into a packet buffer and hands it to the ethernet
// wrapper, which parses the link header.
func (e *Endpoint) deliver(fr []byte) {
	if len(fr) < header.EthernetMinimumSize {
		e.stats.dropped.Add(1)
		return
	}
	e.mu.RLock()
	disp := e.disp
	e.mu.RUnlock()
	if disp == nil {
		e.stats.dropped.Add(1)
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithView(buffer.NewViewWithData(fr)),
	})
	e.stats.rxFrames.Add(1)
	e.stats.rxBytes.Add(uint64(len(fr)))
	// The ethernet wrapper reads the ethertype out of the frame itself, so the
	// number passed here only has to satisfy anything observing the frame,
	// such as -sniff.
	disp.DeliverNetworkPacket(ethertype(fr), pkt)
	pkt.DecRef()
}

// WriteFrame sends a frame the gateway built itself, rather than one the stack
// produced, out to the guest. The ICMP answers the gateway writes travel this
// way. It is safe to call while the stack is also writing: the frame transport
// serialises writes. The error says whether the frame was handed over at all,
// which is what lets a caller count only the answers that left.
func (e *Endpoint) WriteFrame(fr []byte) error {
	e.mu.RLock()
	conn, closed, stalled := e.conn, e.closed, e.writeErr
	e.mu.RUnlock()
	if closed {
		return errLinkGone
	}
	// The reason the link went away, when a write is what put it down: it says
	// more to the caller than "gone", and it saves waiting on a transport that
	// has already refused this session's frames.
	if stalled != nil {
		return stalled
	}
	if conn == nil {
		return errLinkGone
	}

	fr = padRunt(fr)
	if err := conn.WriteFrame(fr); err != nil {
		e.stats.dropped.Add(1)
		e.noteWriteFailure(conn, err)
		return err
	}
	e.stats.txFrames.Add(1)
	e.stats.txBytes.Add(uint64(len(fr)))
	return nil
}

// noteWriteFailure puts the link down after the transport refused a qemu.
//
// A transport that refused one frame refuses the rest, and a guest whose frames
// are not going out has a link that is not working, so this is where the session
// is ended: the transport is closed, which unblocks Run, and the session's exit
// clears the relays and the budget the guest was holding. The reason is remembered
// so that Run can report the stall instead of a close that was our own doing, and
// so that later writes fail at once rather than waiting on the same dead transport.
func (e *Endpoint) noteWriteFailure(conn qemu.Conn, err error) {
	e.mu.Lock()
	first := e.writeErr == nil
	if first {
		e.writeErr = err
	}
	if e.conn == conn {
		e.conn = nil
	}
	e.mu.Unlock()

	if first {
		_ = conn.Close()
	}
}
