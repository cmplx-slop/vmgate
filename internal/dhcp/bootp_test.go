package dhcp

import (
	"bytes"
	"encoding/binary"
	"testing"

	"vmgate/internal/testutil"
)

// rfcCookie is the magic cookie as RFC 1048 names it: the address
// 99.130.83.99. Spelled out here rather than read from magicCookie so that a
// change to one does not quietly change the other.
var rfcCookie = []byte{0x63, 0x82, 0x53, 0x63}

// wireDISCOVER assembles a DISCOVER the way a client assembles it: fixed
// fields, then the cookie, then options as raw bytes. Nothing here goes
// through Marshal, which is the point: a test that encodes and decodes with the
// same code cannot notice bytes that are wrong for everyone else.
func wireDISCOVER(cookie []byte, mac []byte, xid uint32) []byte {
	opts := []byte{
		OptMessageType, 1, Discover,
		// The client identifier dhclient always sends: hardware type then MAC.
		61, byte(len(mac) + 1), 1,
	}
	opts = append(opts, mac...)
	opts = append(opts,
		60, 4, 'd', 'h', 'c', 'p', // vendor class
		55, 4, OptSubnetMask, OptRouter, OptDNS, OptLeaseTime, // what it wants back
		OptEnd,
	)
	// Pad the way a client does, so the message is over the 300 byte minimum.
	for len(opts) < 64 {
		opts = append(opts, OptPad)
	}

	b := make([]byte, fixedSize+4+len(opts))
	b[0] = OpBootpRequest
	b[1] = 1 // ethernet
	b[2] = byte(len(mac))
	binary.BigEndian.PutUint32(b[4:8], xid)
	binary.BigEndian.PutUint16(b[10:12], FlagBroadcast)
	copy(b[28:28+len(mac)], mac)
	copy(b[fixedSize:fixedSize+4], cookie)
	copy(b[fixedSize+4:], opts)
	return b
}

// TestParseReadsWhatAClientSends is the whole reason the cookie constant is
// worth a test of its own: dhclient puts the RFC's cookie in its request, and a
// server that expects anything else never reaches the options and answers
// nothing at all.
func TestParseReadsWhatAClientSends(t *testing.T) {
	mac := testutil.MAC(t, "52:54:00:12:34:56")
	b := wireDISCOVER(rfcCookie, mac, 0x99aabbcc)

	m, err := Parse(b)
	if err != nil {
		t.Fatalf("parse a client's DISCOVER: %v", err)
	}
	if m.Type() != Discover {
		t.Fatalf("message type is %s, want DISCOVER", TypeString(m.Type()))
	}
	if got := m.HardwareAddress(); !bytes.Equal(got, mac) {
		t.Fatalf("chaddr = %v, want %v", got, mac)
	}
	if m.XID != 0x99aabbcc {
		t.Fatalf("xid = %x, want 99aabbcc", m.XID)
	}
	if m.Flags&FlagBroadcast == 0 {
		t.Error("the broadcast flag was not read, so the reply would go unicast")
	}
	if _, ok := m.Options.Get(55); !ok {
		t.Error("the parameter request list was not read")
	}
}

// TestParseRefusesAnotherCookie keeps the refusal honest, including against the
// transposed cookie this package used to carry: accepting it would mean
// answering a client that is not speaking DHCP.
func TestParseRefusesAnotherCookie(t *testing.T) {
	mac := testutil.MAC(t, "52:54:00:12:34:56")
	for _, cookie := range [][]byte{
		{0x63, 0x82, 0x45, 0x36}, // the transposition this package once shipped
		{0, 0, 0, 0},
		{0x63, 0x82, 0x53, 0x62},
	} {
		if _, err := Parse(wireDISCOVER(cookie, mac, 1)); err != ErrCookie {
			t.Errorf("cookie % x: err = %v, want %v", cookie, err, ErrCookie)
		}
	}
}

// TestMarshalWritesTheCookieTheRFCNames matters as much as reading it: a reply
// with the wrong four bytes is a reply no client will open, however correct the
// options inside it are.
func TestMarshalWritesTheCookieTheRFCNames(t *testing.T) {
	mac := testutil.MAC(t, "52:54:00:12:34:56")
	m := &Message{
		Op:     OpBootpReply,
		HType:  1,
		HLen:   6,
		XID:    7,
		CHAddr: mac,
	}
	m.Options.Set(OptMessageType, []byte{Offer})

	b := m.Marshal()
	if len(b) < fixedSize+8 {
		t.Fatalf("marshalled message is %d bytes", len(b))
	}
	if got := b[fixedSize : fixedSize+4]; !bytes.Equal(got, rfcCookie) {
		t.Fatalf("magic cookie = % x, want % x (99.130.83.99)", got, rfcCookie)
	}
	if back, err := Parse(b); err != nil {
		t.Fatalf("parse our own reply: %v", err)
	} else if back.Type() != Offer {
		t.Fatalf("round trip gives %s, want OFFER", TypeString(back.Type()))
	}
}
