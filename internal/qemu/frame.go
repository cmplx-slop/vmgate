package qemu

import "errors"

// Frame size limits. 65535 is the largest length QEMU will prefix; 60 is the
// smallest frame a real NIC puts on the wire (14 byte header plus the 46 byte
// minimum payload, with the FCS stripped by the NIC). Stack implementations
// are not that strict though: an ARP request is only 42 bytes, so a receiver
// must accept anything that at least has an ethernet header.
const (
	MaxFrameSize = 65535
	MinFrameSize = 60

	// minEthernet is the length of an ethernet header, and so the shortest
	// thing a receiver can be asked to treat as a frame.
	minEthernet = 14
)

// Errors returned by the framing layer.
var (
	// ErrShortRead signals that the peer vanished in the middle of a frame.
	ErrShortRead = errors.New("qemu: short read")

	// ErrBadLength signals a length that cannot describe a frame.
	ErrBadLength = errors.New("qemu: bad frame length")

	// ErrStalled signals a peer that stopped taking frames, which is a link that
	// has to be replaced rather than waited for.
	ErrStalled = errors.New("qemu: the peer is not taking frames")
)

// Conn is a bidirectional, frame delimited byte transport.
type Conn interface {
	// ReadFrame returns the next whole ethernet frame. The returned slice
	// is only valid until the next call to ReadFrame. It returns io.EOF
	// when the peer closed the connection cleanly.
	ReadFrame() ([]byte, error)

	// WriteFrame sends one whole ethernet frame. It is not asked to wait
	// forever for a peer that has stopped reading: frame.Stream bounds the wait
	// and gives up on the stream when it runs out, which is what lets the link
	// session end rather than park.
	WriteFrame(frame []byte) error

	Close() error
}

// Stats counts the traffic that passed through a Stream.
type Stats struct {
	FramesIn  int64
	BytesIn   int64
	FramesOut int64
	BytesOut  int64
	BadFrames int64
}
