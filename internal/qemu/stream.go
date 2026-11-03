package qemu

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Stream implements Conn on top of a reliable byte stream, such as the socket
// QEMU opens for -netdev stream.
//
// One goroutine may call ReadFrame while another calls WriteFrame; concurrent
// calls of the same method are serialised. Closing the stream unblocks a
// pending ReadFrame, because the underlying net.Conn reports the close.
//
// A write waits for the peer for at most writeTimeout, and once one has failed
// the stream refuses the rest: see WriteFrame.
type Stream struct {
	c    net.Conn
	r    *bufio.Reader
	rbuf []byte

	readMu  sync.Mutex
	writeMu sync.Mutex

	// writeWait is how long one write may wait for the peer; writeErr is
	// why the stream stopped taking writes, if it did.
	writeWait time.Duration
	writeErr  error

	framesIn  atomic.Int64
	bytesIn   atomic.Int64
	framesOut atomic.Int64
	bytesOut  atomic.Int64
	badFrames atomic.Int64
}

// writeTimeout is how long one frame may wait for the peer to take it.
//
// A guest that has stopped taking frames is a guest whose device has stopped, and
// waiting for it is not a neutral choice: the link's read loop answers some frames
// where it reads them, so a guest that will not take an answer stops being read as
// well, and nothing about the session says so. Two seconds is long enough that a
// guest which is merely busy never reaches it.
const writeTimeout = 2 * time.Second

// NewStream returns a Conn that exchanges frames over c.
func NewStream(c net.Conn) *Stream {
	return &Stream{
		c:         c,
		r:         bufio.NewReaderSize(c, 64*1024),
		writeWait: writeTimeout,
	}
}

// setWriteTimeout shortens the wait one write will spend on a peer. It is for
// tests, which cannot wait two seconds to find out that a peer has gone away.
func (s *Stream) setWriteTimeout(d time.Duration) { s.writeWait = d }

// NewPipe returns a frame connection joined to an in-memory peer, plus that
// peer. It replaces a QEMU socket in tests: frames written by the peer arrive
// on the returned Conn and vice versa.
func NewPipe() (*Stream, *Stream) {
	a, b := net.Pipe()
	return NewStream(a), NewStream(b)
}

// Stats returns a snapshot of the traffic counters.
func (s *Stream) Stats() Stats {
	return Stats{
		FramesIn:  s.framesIn.Load(),
		BytesIn:   s.bytesIn.Load(),
		FramesOut: s.framesOut.Load(),
		BytesOut:  s.bytesOut.Load(),
		BadFrames: s.badFrames.Load(),
	}
}

// ReadFrame implements Conn.
//
// The frame it returns shares a buffer with the stream and is only good until
// the next ReadFrame on the same Stream: a caller that keeps a frame, or hands
// it to another goroutine, has to copy it first.
func (s *Stream) ReadFrame() ([]byte, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	f, e := s.readLenPrefix()
	if e != nil {
		if e != io.EOF {
			s.badFrames.Add(1)
		}
		return nil, e
	}
	if len(f) < minEthernet {
		s.badFrames.Add(1)
		return nil, ErrBadLength
	}
	s.framesIn.Add(1)
	s.bytesIn.Add(int64(len(f)))
	return f, nil
}

func (s *Stream) readLenPrefix() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrShortRead
		}
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < minEthernet || n > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d", ErrBadLength, n)
	}
	if cap(s.rbuf) < int(n) {
		s.rbuf = make([]byte, n)
	}
	buf := s.rbuf[:n]
	if _, err := io.ReadFull(s.r, buf); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, ErrShortRead
		}
		return nil, err
	}
	return buf, nil
}

// WriteFrame implements Conn.
//
// The write waits for the peer for at most the stream's write timeout, and a
// stream that has failed one write refuses the ones after it. Both are about the
// same thing: a frame that was part written cannot be followed by a whole one, so
// a peer that stopped taking frames has broken the framing, and there is nothing
// to recover except a new connection.
func (s *Stream) WriteFrame(frame []byte) error {
	if len(frame) > MaxFrameSize {
		return fmt.Errorf("%w: %d", ErrBadLength, len(frame))
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.writeErr != nil {
		return s.writeErr
	}
	// A transport that cannot be given a deadline is written to anyway: the wait
	// is a guard against a stuck guest, not part of the framing.
	_ = s.c.SetWriteDeadline(time.Now().Add(s.writeWait))

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(frame)))
	if _, err := s.c.Write(append(hdr[:len(hdr):len(hdr)], frame...)); err != nil {
		s.writeErr = s.gaveUp(err)
		return s.writeErr
	}
	s.framesOut.Add(1)
	s.bytesOut.Add(int64(len(frame)))
	return nil
}

// gaveUp names what a failed write means. A wait that ran out says the guest has
// stopped taking frames, which is worth saying in as many words; anything else is
// the transport's own trouble and is passed through.
func (s *Stream) gaveUp(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("%w after %v", ErrStalled, s.writeWait)
	}
	return err
}

// Close closes the underlying connection. There is no nil check because a
// Stream always has one: NewStream and NewPipe are the only ways to make it.
func (s *Stream) Close() error {
	return s.c.Close()
}
