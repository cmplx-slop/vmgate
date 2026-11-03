package ethlink

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"vmgate/internal/qemu"
	"vmgate/internal/testutil"
)

// TestTransportThatStopsTakingFramesEndsTheLink pins what the gateway does when
// the link's transport gives up on a guest: the session is over. The alternative
// is that the guest that stopped taking frames is never noticed, and a gateway
// that serves one guest at a time would keep refusing the next one forever.
func TestTransportThatStopsTakingFramesEndsTheLink(t *testing.T) {
	e := New(1500, macGW, false)
	defer e.Close()

	c := newStalledConn()
	e.SetConn(c)

	written := make(chan error, 1)
	go func() { written <- e.WriteFrame(echoFrame(1)) }()

	// The write waits, as it should: the stack is told what really left. Then the
	// transport says it is finished with this guest.
	c.giveUp()

	select {
	case err := <-written:
		if !errors.Is(err, qemu.ErrStalled) {
			t.Errorf("the stalled write returned %v, want the stalled transport", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled write was never given up on")
	}

	// Closing the transport is how Run finds out the session is over, and how the
	// guest's side hears about it too.
	testutil.Within(2*time.Second, func() bool { return c.isClosed() })
	if !c.isClosed() {
		t.Error("the transport was left open, so nothing ended the session")
	}

	// A second frame is not tried against a transport that is done with. Every
	// answer the gateway still tries to send fails at once, which is what keeps a
	// wedged guest from costing the gateway a wait per qemu.
	calls := c.writeCalls()
	if err := e.WriteFrame(echoFrame(2)); !errors.Is(err, qemu.ErrStalled) {
		t.Errorf("writing after the transport gave up returned %v", err)
	}
	if got := c.writeCalls(); got != calls {
		t.Errorf("the dead transport was written to %d more times, want not again", got-calls)
	}
	if e.Stats().Dropped == 0 {
		t.Error("the frame that could not be written was not counted as dropped")
	}

	// A new transport is a new guest, or the same one after a reboot: it gets the
	// same chance rather than inheriting the failure.
	fresh := &willingConn{closed: make(chan struct{})}
	e.SetConn(fresh)
	if err := e.WriteFrame(echoFrame(3)); err != nil {
		t.Errorf("a new transport was refused: %v", err)
	}
	if got := len(fresh.written()); got != 1 {
		t.Errorf("the new transport took %d frames, want the one frame offered", got)
	}
}

// TestAnswerThatCannotBeWrittenEndsTheSession is the shape of the problem the
// test above is about: Run hands a guest frame to the stack inline, and an answer
// written there, whether an ARP reply or the gateway's own answer to a ping, is
// written on the same goroutine that reads that guest. So a write that gives up
// has to end the session, and the read loop must not simply stop.
func TestAnswerThatCannotBeWrittenEndsTheSession(t *testing.T) {
	e := New(1500, macGW, false)
	defer e.Close()

	c := newStalledConn()
	e.SetConn(c)

	// The hook answers every frame it sees, which is what an ICMP echo answer
	// does: it writes back to the guest the frame came from.
	e.SetInspect(func([]byte) bool {
		_ = e.WriteFrame(echoFrame(1))
		return false
	})

	done := make(chan error, 1)
	go func() { done <- e.Run() }()

	c.in <- echoFrame(1) // the guest asks for something the gateway answers
	c.giveUp()           // the answer cannot be delivered

	select {
	case err := <-done:
		if !errors.Is(err, qemu.ErrStalled) {
			t.Errorf("the session ended with %v, want the stalled transport as the reason", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop outlived a transport that cannot write")
	}
}

// stalledConn is a frame transport with a guest that has stopped taking frames:
// the first write waits until it is given up on, and every write after that is
// refused at once. That is what qemu.Stream does, and the endpoint is written
// against that behaviour rather than against a transport that blocks forever.
type stalledConn struct {
	in     chan []byte
	closed chan struct{}
	once   sync.Once

	// abandoned is closed to say the peer did not take the frame, which is what
	// the real transport's write timeout decides on its own.
	abandoned chan struct{}

	mu       sync.Mutex
	attempts int
	err      error
}

func newStalledConn() *stalledConn {
	return &stalledConn{
		in:        make(chan []byte),
		closed:    make(chan struct{}),
		abandoned: make(chan struct{}),
	}
}

// giveUp says the peer has not taken the frame, which is what the transport's own
// write timeout decides in the real thing.
func (c *stalledConn) giveUp() {
	select {
	case <-c.abandoned:
	default:
		close(c.abandoned)
	}
}

func (c *stalledConn) ReadFrame() ([]byte, error) {
	select {
	case fr := <-c.in:
		return fr, nil
	case <-c.closed:
		return nil, net.ErrClosed
	}
}

func (c *stalledConn) WriteFrame(fr []byte) error {
	c.mu.Lock()
	c.attempts++
	first := c.err == nil && c.attempts == 1
	c.mu.Unlock()

	if first {
		<-c.abandoned
		c.mu.Lock()
		defer c.mu.Unlock()
		c.err = fmt.Errorf("%w after waiting for the guest", qemu.ErrStalled)
		return c.err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *stalledConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *stalledConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *stalledConn) writeCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.attempts
}

// willingConn is a transport that takes every frame, used to show that a fresh
// session is not held to the failure of the one before it.
type willingConn struct {
	closed chan struct{}
	once   sync.Once

	mu     sync.Mutex
	frames [][]byte
}

func (c *willingConn) ReadFrame() ([]byte, error) {
	<-c.closed
	return nil, net.ErrClosed
}

func (c *willingConn) WriteFrame(fr []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frames = append(c.frames, append([]byte(nil), fr...))
	return nil
}

func (c *willingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *willingConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.frames
}

// echoFrame is one ping with a payload that says which frame it is.
func echoFrame(n int) []byte {
	return EchoFrame(EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, uint16(n), []byte{byte(n)}))
}
