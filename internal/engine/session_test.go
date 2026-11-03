package engine_test

import (
	"testing"
	"time"

	"vmgate/internal/fixture"
	"vmgate/internal/qemu"
)

// The link is built for one guest at a time: the endpoint holds a single frame
// transport, so a second session would replace the first one's, and when the
// first one finished it would clear the relays the second one was still using.
// The command accepts one QEMU connection at a time, so this only ever fires on
// a mistake — but the mistake is worse than an error, and it is the sort of
// thing a "let the guest reconnect faster" change would introduce.
func TestSecondLinkSessionIsRefused(t *testing.T) {
	r := fixture.Link(t, nil)

	// The fixture starts its session in a goroutine, so wait for it to be the
	// running one before trying to take the link away from it.
	deadline := time.Now().Add(10 * time.Second)
	for r.Eng.Serving() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the fixture's link session never started")
		}
		time.Sleep(5 * time.Millisecond)
	}

	hostSide, _ := qemu.NewPipe()
	if err := r.Eng.ServeFrame(hostSide); err == nil {
		t.Fatal("a second session was accepted while one was already running")
	}
	if n := r.Eng.Serving(); n != 1 {
		t.Errorf("serving = %d, want the one session that was already running", n)
	}

	// The session that was running is untouched: a ping is still answered.
	got := echoFrames(t, r)
	ping(t, r, r.Cfg.GatewayIP, 5, 1, []byte("mine"))

	if echo := wantEcho(t, got, 3*time.Second); !echo.SrcIP.Equal(r.Cfg.GatewayIP) {
		t.Errorf("answer came from %s, want the gateway itself", echo.SrcIP)
	}
}
