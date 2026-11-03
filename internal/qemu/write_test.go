package qemu

import (
	"errors"
	"testing"
	"time"
)

// TestStreamGivesUpOnAPeerThatStopsReading is about the guest that has stopped
// taking frames: a wedged kernel, or a device model that went away. Waiting for it
// is not a neutral answer, because a frame that was part written cannot be
// followed by a whole one, so the wait is bounded and one failure ends the
// stream's writing for good.
func TestStreamGivesUpOnAPeerThatStopsReading(t *testing.T) {
	const wait = 50 * time.Millisecond

	a, b := NewPipe()
	defer a.Close()
	defer b.Close()
	a.setWriteTimeout(wait)

	// Nothing reads b, so a's frame has nowhere to go.
	start := time.Now()
	err := a.WriteFrame(ipv4Frame(60))
	elapsed := time.Since(start)
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("writing to a peer that is not reading returned %v, want the stall", err)
	}
	if elapsed < wait {
		t.Errorf("the write gave up after %v, want the %v it was promised", elapsed, wait)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the write waited %v, far longer than the %v timeout", elapsed, wait)
	}

	// The rest of the frames on that stream are refused at once rather than
	// waited for again: the framing there is already ruined.
	start = time.Now()
	if err := a.WriteFrame(ipv4Frame(60)); !errors.Is(err, ErrStalled) {
		t.Errorf("the frame after the stall returned %v", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("a stream that had given up waited %v to say so", d)
	}

	// Giving up on writing is not giving up on the link: the other direction
	// still works, and a peer that was only busy reading keeps being heard.
	writeErr := make(chan error, 1)
	go func() { writeErr <- b.WriteFrame(ipv4Frame(60)) }()

	fr, err := a.ReadFrame()
	if err != nil {
		t.Fatalf("reading after a failed write: %v", err)
	}
	if len(fr) == 0 {
		t.Error("the frame that arrived after the failed write was empty")
	}
	if err := <-writeErr; err != nil {
		t.Errorf("writing in the other direction: %v", err)
	}
}

// TestPeerThatReadsInTimeIsNotPenalised keeps the bound honest in the other
// direction: a stream whose peer takes frames is never shortened by the deadline
// that is set before every write.
func TestPeerThatReadsInTimeIsNotPenalised(t *testing.T) {
	a, b := NewPipe()
	defer a.Close()
	defer b.Close()
	a.setWriteTimeout(10 * time.Millisecond)

	go func() {
		for range 8 {
			if _, err := b.ReadFrame(); err != nil {
				return
			}
		}
	}()

	for i := range 8 {
		if err := a.WriteFrame(ipv4Frame(60)); err != nil {
			t.Fatalf("write %d to a peer that is reading: %v", i, err)
		}
	}
	if got := a.Stats().FramesOut; got != 8 {
		t.Errorf("frames written = %d, want all eight", got)
	}
}
