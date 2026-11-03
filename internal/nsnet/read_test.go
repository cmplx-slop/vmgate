package nsnet

import (
	"io"
	"testing"
)

// The stack demands that a Writer which reports no error took the whole packet,
// and panics otherwise. A datagram longer than the reader's buffer is the
// ordinary way to meet that: a guest sends one to the DNS service, the VPN peer
// answers a query with one, a ping is answered with more than the gateway asked
// for. So the copy helper has to say when it ran out of room, and the tests for
// it are the difference between a truncated datagram and a dead gateway.
func TestSliceWriterSaysWhenItCouldNotTakeTheWrite(t *testing.T) {
	buf := make([]byte, 64)
	w := sliceWriter(buf)

	n, err := w.Write(make([]byte, 100))
	if err == nil {
		t.Fatalf("writing 100 bytes into 64 returned (%d, nil): the stack panics on that", n)
	}
	if n != 64 {
		t.Errorf("short write reported %d bytes, want the 64 that fitted", n)
	}

	// What does fit is still taken without complaint, which is every read that
	// is not oversized.
	full := sliceWriter(make([]byte, 100))
	if n, err := full.Write(make([]byte, 64)); n != 64 || err != nil {
		t.Errorf("writing 64 bytes into 100 returned (%d, %v), want (64, nil)", n, err)
	}
}

// A short write leaves the writer where it stopped rather than unwound, which is
// what the stack reads as "this is all the caller got".
func TestSliceWriterKeepsItsPositionAcrossChunks(t *testing.T) {
	w := sliceWriter(make([]byte, 10))

	if n, err := w.Write(make([]byte, 6)); n != 6 || err != nil {
		t.Fatalf("first chunk returned (%d, %v), want (6, nil)", n, err)
	}
	n, err := w.Write(make([]byte, 8))
	if err != io.ErrShortWrite {
		t.Errorf("second chunk returned error %v, want %v", err, io.ErrShortWrite)
	}
	if n != 4 {
		t.Errorf("second chunk took %d bytes, want the 4 that were left", n)
	}
}
