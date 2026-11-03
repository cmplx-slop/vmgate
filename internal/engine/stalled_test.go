package engine_test

import (
	"errors"
	"testing"
	"time"

	"vmgate/internal/ethlink"
	"vmgate/internal/fixture"
	"vmgate/internal/qemu"
	"vmgate/internal/testutil"
)

// TestGuestThatStopsTakingFramesIsDisconnected is about a guest that stops taking
// frames: a wedged kernel, or a QEMU device model that stopped, neither of which
// needs privilege or forgery. The gateway answers some frames on the goroutine
// that read them, so such a guest used to be able to keep its session forever
// without anyone noticing: the answer to one ping waited, the read loop waited
// with it, and the session kept its relays and its share of the budget in front of
// every guest that came after. The frame transport gives up on a guest that will
// not take frames, the session ends, and the next guest is let in.
func TestGuestThatStopsTakingFramesIsDisconnected(t *testing.T) {
	r := fixture.Link(t, nil)

	// One ping, from a guest that reads nothing afterwards: that is what a wedged
	// guest looks like from this side. The gateway answers it on the goroutine
	// that read it, which is where the wedge starts.
	req := ethlink.EchoRequest(guestAddr, r.Cfg.MAC, guestIP, r.Cfg.GatewayIP,
		7, 1, []byte("x"))
	if err := r.Frames.WriteFrame(ethlink.EchoFrame(req)); err != nil {
		t.Fatalf("pinging the gateway: %v", err)
	}

	// The session has to end. When it ends is decided by the transport's own
	// write timeout, which is bounded, rather than by a guest that has stopped
	// behaving.
	testutil.Within(20*time.Second, func() bool { return r.Eng.Serving() == 0 })
	if n := r.Eng.Serving(); n != 0 {
		t.Fatalf("sessions = %d, want the wedged guest's session to have ended", n)
	}
	if got := r.Eng.Stats().Link.Dropped; got == 0 {
		t.Error("the frame that could not be written was not counted as dropped")
	}

	// The next guest can have the link. This is the part the wedged session made
	// impossible, because the gateway never found out it was there.
	guestSide, hostSide := qemu.NewPipe()
	defer guestSide.Close()
	go func() { _ = r.Eng.ServeFrame(hostSide) }()

	testutil.Within(10*time.Second, func() bool { return r.Eng.Serving() == 1 })
	if n := r.Eng.Serving(); n != 1 {
		t.Fatalf("sessions = %d after the wedged guest was dropped, want the new guest's", n)
	}

	again := ethlink.EchoRequest(guestAddr, r.Cfg.MAC, guestIP, r.Cfg.GatewayIP,
		9, 1, []byte("new"))
	if err := guestSide.WriteFrame(ethlink.EchoFrame(again)); err != nil {
		t.Fatalf("the new guest's ping: %v", err)
	}

	answers := make(chan ethlink.Echo, 1)
	problems := make(chan error, 1)
	go func() {
		fr, err := guestSide.ReadFrame()
		if err != nil {
			problems <- err
			return
		}
		echo, ok := ethlink.ParseEcho(fr)
		if !ok {
			problems <- errors.New("the answer is not an echo")
			return
		}
		answers <- echo
	}()

	select {
	case echo := <-answers:
		if echo.Ident != 9 {
			t.Errorf("the new guest's answer carries ident %d, want 9", echo.Ident)
		}
	case err := <-problems:
		t.Fatalf("reading the new guest's answer: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the new guest was not answered")
	}
}
