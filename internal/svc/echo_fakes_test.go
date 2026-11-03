package svc

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
)

// answer is what a pretend far side hands back.
type answer struct {
	seq     uint16
	payload []byte
}

// fakeEchoPath is the far side of a ping: it remembers the requests it was sent
// and answers with whatever the test puts in answers. The byte level work is
// nsnet's, and tested there; this stands where the tunnel socket stands.
type fakeEchoPath struct {
	mu      sync.Mutex
	sends   []answer
	answers chan answer
	closed  chan struct{}
	once    sync.Once
}

func newFakeEchoPath() *fakeEchoPath {
	return &fakeEchoPath{
		answers: make(chan answer, 8),
		closed:  make(chan struct{}),
	}
}

func (p *fakeEchoPath) Send(seq uint16, payload []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sends = append(p.sends, answer{seq: seq, payload: append([]byte(nil), payload...)})
	return nil
}

func (p *fakeEchoPath) Answer(buf []byte) (uint16, []byte, error) {
	select {
	case a := <-p.answers:
		return a.seq, a.payload, nil
	case <-p.closed:
		return 0, nil, io.EOF
	}
}

func (p *fakeEchoPath) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}

// ident is the pretend socket identifier: what the far side of the tunnel would
// have chosen for this path.
func (p *fakeEchoPath) Ident() uint16 { return 0x1234 }

// sent is the last request the relay wrote, which is what a test checks first.
func (p *fakeEchoPath) sent() (uint16, []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.sends) == 0 {
		return 0, nil
	}
	last := p.sends[len(p.sends)-1]
	return last.seq, last.payload
}

// deadEchoPath is an echo path that is willing to be opened and refuses every
// request, which is what a relay reaped under a ping, or a tunnel that went
// away, looks like from the sending side.
type deadEchoPath struct{}

func (deadEchoPath) Send(uint16, []byte) error { return errors.New("icmp: path is gone") }

func (deadEchoPath) Answer([]byte) (uint16, []byte, error) {
	return 0, nil, errors.New("icmp: path is gone")
}

func (deadEchoPath) Close() error { return nil }

func (deadEchoPath) Ident() uint16 { return 0xffff }

// loggedBuffer collects what a manager logged. The log is written from the
// relay's own goroutine, so the test that reads it has to lock: an unprotected
// bytes.Buffer here is a race in the test, not in the gateway.
type loggedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *loggedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *loggedBuffer) contains(want string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Contains(l.b.String(), want)
}

func (l *loggedBuffer) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// panickingEchoPath is a path out of the tunnel that fails the way an internal
// invariant does: it does not return an error, it brings the goroutine down.
type panickingEchoPath struct {
	closed chan struct{}
	once   sync.Once
}

func (p *panickingEchoPath) Send(uint16, []byte) error { return nil }

func (p *panickingEchoPath) Answer([]byte) (uint16, []byte, error) {
	panic("probe: a packet shape nobody predicted")
}

func (p *panickingEchoPath) Ident() uint16 { return 0x99 }

func (p *panickingEchoPath) Close() error {
	p.once.Do(func() { close(p.closed) })
	return nil
}
