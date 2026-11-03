package qemu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// ipv4Frame builds a minimal ethernet + IPv4 frame with a given payload.
func ipv4Frame(payload int) []byte {
	if payload < 46 {
		payload = 46 // the minimum ethernet payload
	}
	ipLen := 20 + payload
	b := make([]byte, 14+ipLen)
	copy(b[0:], bytes.Repeat([]byte{0x52}, 6))
	copy(b[6:], bytes.Repeat([]byte{0x62}, 6))
	binary.BigEndian.PutUint16(b[12:], 0x0800)

	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:], uint16(ipLen))
	b[23] = 6 // protocol: TCP
	copy(b[28:], net.IPv4(10, 0, 2, 2).To4())
	copy(b[32:], net.IPv4(10, 0, 2, 15).To4())
	for i := range payload {
		b[34+i] = byte(i)
	}
	return b
}

// writeAsync sends frames in the background, in order. net.Pipe is unbuffered,
// so each write only completes once the far side reads it.
func writeAsync(s *Stream, frames ...[]byte) []<-chan error {
	send := make([]chan error, len(frames))
	out := make([]<-chan error, len(frames))
	for i := range send {
		send[i] = make(chan error, 1)
		out[i] = send[i]
	}
	go func() {
		for i, fr := range frames {
			send[i] <- s.WriteFrame(fr)
		}
	}()
	return out
}

func TestRoundTrip(t *testing.T) {
	a, b := NewPipe()
	defer a.Close()
	defer b.Close()

	want := [][]byte{
		ipv4Frame(20),
		ipv4Frame(1400),
		bytes.Repeat([]byte{0xAB}, 60), // not an IP frame at all: still a frame
	}
	writes := writeAsync(b, want...)

	for i, fr := range want {
		got, err := a.ReadFrame()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(got, fr) {
			t.Errorf("frame %d: got %d bytes, want %d", i, len(got), len(fr))
		}
		if err := <-writes[i]; err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
}

func TestBidirectional(t *testing.T) {
	a, b := NewPipe()
	defer a.Close()
	defer b.Close()

	w1 := writeAsync(a, ipv4Frame(60))
	w2 := writeAsync(b, ipv4Frame(80))

	for _, s := range []*Stream{b, a} {
		fr, err := s.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(fr) < 60 {
			t.Fatalf("frame too short: %d", len(fr))
		}
	}
	for _, ws := range [][]<-chan error{w1, w2} {
		for _, w := range ws {
			if err := <-w; err != nil {
				t.Fatalf("write: %v", err)
			}
		}
	}
	if st := a.Stats(); st.FramesOut != 1 || st.FramesIn != 1 {
		t.Fatalf("counters: %+v", st)
	}
}

// TestRejectsRubbishLength checks that a nonsense length prefix is reported
// instead of being used to size a read, which would hang or explode.
func TestRejectsRubbishLength(t *testing.T) {
	a, b := NewPipe()
	defer a.Close()
	defer b.Close()

	raw := b.c // the unwrapped stream, so we can write an unprefixed length
	go func() {
		if _, err := raw.Write([]byte{0x00, 0x00, 0x00, 0x01}); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	if _, err := a.ReadFrame(); !errors.Is(err, ErrBadLength) {
		t.Fatalf("read error = %v, want ErrBadLength", err)
	}
}

// TestCloseUnblocksReader is what lets the engine tear a session down without
// waiting for the guest to say goodbye.
func TestCloseUnblocksReader(t *testing.T) {
	a, b := NewPipe()
	defer b.Close()

	done := make(chan error, 1)
	go func() {
		_, err := a.ReadFrame()
		done <- err
	}()
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded on a closed stream")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock the reader")
	}
}
