package engine_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"vmgate/internal/ethlink"
	"vmgate/internal/fixture"
)

// Splitting a ping in two used to be a way past the entire ICMP policy. The
// gateway reads the transport header to decide what a ping may do, and only the
// first fragment carries one, so a fragment was handed to the netstack, which
// reassembles it and answers it with its always-on echo responder, out of the
// address that was pinged. A guest could then be told that the metadata address,
// or a machine on its own segment, or a host the tunnel does not carry, is up —
// and the stats line and the log would show nothing at all, because the frame
// never reached the code that counts and refuses.

func TestFragmentedPingIsNotAnswered(t *testing.T) {
	cases := []struct {
		name string
		dst  string
		why  string
	}{
		{"a host the tunnel does not carry", "203.0.113.9", "refused, not answered"},
		{"the metadata address", "169.254.169.254", "refused by the egress policy"},
		{"a machine on its own segment", "10.0.2.99", "refused as the guest's own subnet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fixture.Link(t, nil)
			if !r.VPN.Handshake(5 * time.Second) {
				t.Fatal("the tunnel never came up")
			}

			got := echoFrames(t, r)
			writeFragmentedPing(t, r, net.ParseIP(tc.dst), 4, 1, []byte("split ping"))

			noEcho(t, got, 2*time.Second)

			s := r.Eng.Stats()
			if s.EchoAnswered != 0 || s.EchoRelayed != 0 {
				t.Errorf("answered/relayed = %d/%d, want 0/0: %s",
					s.EchoAnswered, s.EchoRelayed, tc.why)
			}
			if s.Denied == 0 {
				t.Error("nothing was counted, so an operator cannot see this happening")
			}
			if s.Link.Held < 2 {
				t.Errorf("the link held %d frames, want both fragments taken from the stack",
					s.Link.Held)
			}
		})
	}
}

// writeFragmentedPing sends one echo request as two IPv4 fragments: the first
// carries the ICMP header, the second the payload, and both say more fragments
// or an offset so that only the stack would put them back together.
func writeFragmentedPing(t *testing.T, r *fixture.Raw, dst net.IP, ident, seq uint16, payload []byte) {
	t.Helper()

	const ethLen, ipLen, icmpLen = 14, 20, 8
	full := ethlink.EchoFrame(
		ethlink.EchoRequest(guestAddr, r.Cfg.MAC, guestIP, dst, ident, seq, payload))

	// The first piece is the ethernet and IPv4 headers plus the ICMP header,
	// with "more fragments" set; the second is the rest of the payload at an
	// offset of one ICMP header, counted in eight-byte units as IPv4 requires.
	first := append([]byte(nil), full[:ethLen+ipLen+icmpLen]...)
	second := append([]byte(nil), full[:ethLen+ipLen]...)
	second = append(second, full[ethLen+ipLen+icmpLen:]...)
	setFragment(first, 0x5051, 0x20, 0)
	setFragment(second, 0x5051, 0x00, icmpLen/8)

	for i, fr := range [][]byte{first, second} {
		if err := r.Frames.WriteFrame(fr); err != nil {
			t.Fatalf("write fragment %d: %v", i+1, err)
		}
	}
}

// setFragment rewrites the IPv4 header of a frame so that it is one piece of a
// larger datagram: the identification has to match the other piece, the total
// length is this piece's, and the flags and fragment offset share two bytes.
func setFragment(fr []byte, id uint16, flags uint8, offset uint16) {
	ip := fr[14:]
	binary.BigEndian.PutUint16(ip[2:], uint16(len(fr)-14))
	binary.BigEndian.PutUint16(ip[4:], id)
	binary.BigEndian.PutUint16(ip[6:], uint16(flags)<<5|(offset&0x1fff))
	ip[8] = 64 // TTL
	ip[9] = 1  // ICMP
	binary.BigEndian.PutUint16(ip[10:], 0)
	binary.BigEndian.PutUint16(ip[10:], checksum(ip[:20]))
}
