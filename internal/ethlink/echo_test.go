package ethlink

import (
	"encoding/binary"
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var (
	macGuest = net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44}
	macGW    = net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x00, 0x01}
	ipGuest  = net.ParseIP("10.0.2.15")
	ipGW     = net.ParseIP("10.0.2.2")
)

// A frame the gateway builds has to be readable by a guest and by this package:
// the round trip is where that is cheapest to check, and it also checks the two
// checksums, which are the gateway's responsibility because nothing else in
// this path touches them.
func TestEchoFrameRoundTrip(t *testing.T) {
	req := EchoRequest(macGuest, macGW, ipGuest, ipGW, 7, 3, []byte("abcdefgh"))
	fr := EchoFrame(req)

	if len(fr) != header.EthernetMinimumSize+header.IPv4MinimumSize+8+len("abcdefgh") {
		t.Errorf("frame is %d bytes, want the headers plus the payload", len(fr))
	}
	checkFrameChecksums(t, fr)

	got, ok := ParseEcho(fr)
	if !ok {
		t.Fatal("the frame this package built does not parse")
	}
	if got.Type != TypeEcho {
		t.Errorf("type = %d, want a request", got.Type)
	}
	if got.Ident != 7 || got.Seq != 3 {
		t.Errorf("ident/seq = %d/%d, want 7/3", got.Ident, got.Seq)
	}
	if string(got.Payload) != "abcdefgh" {
		t.Errorf("payload = %q, want it back unchanged", got.Payload)
	}
	if !got.SrcIP.Equal(ipGuest) || !got.DstIP.Equal(ipGW) {
		t.Errorf("addresses = %s to %s, want 10.0.2.15 to 10.0.2.2", got.SrcIP, got.DstIP)
	}
	if got.SrcMAC.String() != macGuest.String() || got.DstMAC.String() != macGW.String() {
		t.Errorf("macs = %s to %s, want the guest's and the gateway's", got.SrcMAC, got.DstMAC)
	}
}

// The answer is the request with both layers turned around and the type moved to
// the answer, which is what a guest matches a ping by.
func TestEchoReverse(t *testing.T) {
	req := EchoRequest(macGuest, macGW, ipGuest, ipGW, 7, 3, []byte("hi"))
	ans := req.Reverse()

	if ans.Type != TypeEchoReply {
		t.Errorf("type = %d, want an answer", ans.Type)
	}
	if !ans.SrcIP.Equal(ipGW) || !ans.DstIP.Equal(ipGuest) {
		t.Errorf("answer goes %s to %s, want it back the way it came", ans.SrcIP, ans.DstIP)
	}
	if ans.SrcMAC.String() != macGW.String() || ans.DstMAC.String() != macGuest.String() {
		t.Errorf("answer macs = %s to %s", ans.SrcMAC, ans.DstMAC)
	}
	if ans.Ident != 7 || ans.Seq != 3 || string(ans.Payload) != "hi" {
		t.Errorf("answer ident/seq/payload = %d/%d/%q, want them carried back", ans.Ident, ans.Seq, ans.Payload)
	}

	// Reversing the answer gets the request back, which is how the relay builds
	// a guest's answer out of the request that opened it.
	back := ans.Reverse()
	if back.Type != TypeEcho || !back.SrcIP.Equal(ipGuest) {
		t.Errorf("reversing twice gave type %d from %s", back.Type, back.SrcIP)
	}
	if req.Payload[0] != 'h' || ans.Payload[0] != 'h' {
		t.Fatal("reversing shared or lost the payload")
	}
	ans.Payload[0] = 'x'
	if req.Payload[0] != 'h' {
		t.Error("the reversed payload shares its backing array with the request")
	}
}

// A frame built by hand, as a guest or an old test would, parses the same as one
// built here. This is the frame that would go over the wire for
// `ping -s 8`: 8 bytes of ICMP header and 8 bytes of data.
func TestParseHandBuiltEcho(t *testing.T) {
	fr := []byte{
		0x52, 0x54, 0x00, 0x00, 0x00, 0x01, // dst: the gateway
		0x52, 0x54, 0x11, 0x22, 0x33, 0x44, // src: the guest
		0x08, 0x00, // ethertype: IPv4
		0x45, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
		64, 1, 0x00, 0x00, // ttl, protocol ICMP, checksum filled in below
		10, 0, 2, 15, // src
		10, 0, 2, 2, // dst
		8, 0, 0x00, 0x00, // type 8 (echo request), code 0, checksum below
		0x00, 0x07, 0x00, 0x03, // ident 7, seq 3
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
	}
	fillChecksums(fr)

	got, ok := ParseEcho(fr)
	if !ok {
		t.Fatal("a hand built echo request did not parse")
	}
	if got.Ident != 7 || got.Seq != 3 || got.Type != TypeEcho {
		t.Errorf("ident/seq/type = %d/%d/%d, want 7/3/8", got.Ident, got.Seq, got.Type)
	}
	if string(got.Payload) != "abcdefgh" {
		t.Errorf("payload = %q, want the eight bytes", got.Payload)
	}
	if got.SrcMAC.String() != macGuest.String() {
		t.Errorf("src mac = %s", got.SrcMAC)
	}
}

// One VLAN tag is looked through, because Classify looks through one too, and the
// answer goes back untagged: this gateway serves an access port, not a trunk.
func TestParseEchoThroughOneVLAN(t *testing.T) {
	req := EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, 1, []byte("x"))
	fr := EchoFrame(req)
	tagged := append([]byte(nil), fr[:12]...)
	tagged = append(tagged, 0x81, 0x00, 0x00, 0x0a) // VLAN id 10
	tagged = append(tagged, fr[12:]...)

	got, ok := ParseEcho(tagged)
	if !ok {
		t.Fatal("a tagged echo request did not parse")
	}
	if !got.DstIP.Equal(ipGW) || got.Ident != 1 {
		t.Errorf("parsed %s ident %d", got.DstIP, got.Ident)
	}
	if ans := EchoFrame(got.Reverse()); binary.BigEndian.Uint16(ans[12:]) != ethTypeIPv4 {
		t.Error("the answer came back carrying a VLAN tag")
	}
}

// Everything the parser turns down: the frame has to be an intact IPv4 ICMP echo
// and nothing else, because whatever passes this gate is something the gateway
// answers on its own.
func TestParseEchoRejects(t *testing.T) {
	good := EchoFrame(EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, 1, []byte("x")))

	cases := []struct {
		name  string
		input []byte
	}{
		{"shorter than a link header", good[:10]},
		{"not ipv4", tagEthType(good, 0x86dd)},
		{"zero length", nil},
		{"icmp too short for a header", chop(good, 14+20+4)},
		{"total length beyond the frame", badTotalLength(good, 200)},
		{"a fragment", setFlags(good, 0x20, 0)},
		{"a later fragment", setFlags(good, 0, 8)},
		{"not icmp", setProtocol(good, 6)},
		{"not an echo", setICMPType(good, 3)},
	}
	for _, c := range cases {
		if _, ok := ParseEcho(c.input); ok {
			t.Errorf("%s parsed as an echo", c.name)
		}
	}
}

// Classify does not speak ICMP: an echo frame is not a flow, and the gateway
// must not open a relay because a guest sent a ping to the same address.
func TestClassifyIgnoresEcho(t *testing.T) {
	fr := EchoFrame(EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, 1, nil))
	if _, ok := Classify(fr); ok {
		t.Error("an echo frame was reported as a TCP or UDP flow")
	}
	if _, ok := ParseEcho(fr); !ok {
		t.Error("the echo frame the gateway answers was not parsed")
	}
	if _, ok := ParseEcho([]byte{1, 2, 3}); ok {
		t.Error("a runt parsed as an echo")
	}
}

// checkFrameChecksums verifies the two checksums the way a receiver that checks
// them does: sum the IPv4 header including its checksum field, and the ICMP
// message including its. A correct packet leaves all ones, which is what
// gVisor's own check looks for. Note that the ICMP sum takes no pseudo header:
// that belongs to TCP and UDP, and gVisor's network layer drops an echo whose
// checksum wrongly includes one.
func checkFrameChecksums(t *testing.T, fr []byte) {
	t.Helper()

	pkt := fr[header.EthernetMinimumSize:]
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		t.Fatalf("the ipv4 header is not valid (%d bytes)", len(pkt))
	}
	if !ip.IsChecksumValid() {
		t.Errorf("ipv4 header checksum %#04x does not verify", ip.Checksum())
	}

	msg := pkt[ip.HeaderLength():ip.TotalLength()]
	if sum := checksum.Checksum(msg, 0); sum != 0xffff {
		t.Errorf("icmp message sums to %#04x, want all ones", sum)
	}
}

// fillChecksums writes the two checksums into a hand built frame, which is what
// a guest would do, so the parser can be fed something real.
func fillChecksums(fr []byte) {
	pkt := fr[header.EthernetMinimumSize:]
	ip := header.IPv4(pkt)
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())

	msg := pkt[ip.HeaderLength():ip.TotalLength()]
	binary.BigEndian.PutUint16(msg[2:], 0)
	binary.BigEndian.PutUint16(msg[2:], ^checksum.Checksum(msg, 0))
}

// The edits below build broken frames out of a good one, so that each case can
// say what it is testing rather than repeating the construction.
func copyFrame(fr []byte) []byte { return append([]byte(nil), fr...) }

func tagEthType(fr []byte, typ uint16) []byte {
	out := copyFrame(fr)
	binary.BigEndian.PutUint16(out[12:], typ)
	return out
}

func chop(fr []byte, n int) []byte { return copyFrame(fr[:n]) }

func badTotalLength(fr []byte, total int) []byte {
	out := copyFrame(fr)
	binary.BigEndian.PutUint16(out[14+2:], uint16(total))
	return out
}

// setFlags writes the flags and fragment offset fields, which share two bytes:
// three flag bits, then a thirteen bit offset.
func setFlags(fr []byte, flags uint8, offset uint16) []byte {
	out := copyFrame(fr)
	out[14+6] = flags | byte(offset>>8)
	out[14+7] = byte(offset)
	return out
}

func setProtocol(fr []byte, proto uint8) []byte {
	out := copyFrame(fr)
	out[14+9] = proto
	return out
}

func setICMPType(fr []byte, typ uint8) []byte {
	out := copyFrame(fr)
	out[14+20] = typ
	return out
}

// The hook has to decide whether the stack may see a frame, and a fragment of an
// ICMP datagram is a frame it has to decide about even though the ICMP header
// may be in a different piece: the netstack reassembles, and its echo responder
// then answers for whatever address the datagram named. So the question "is this
// a piece of ICMP, and where is it going" is asked without the header, and it
// has to agree with the frames ParseEcho refuses.
func TestICMPFragmentNamesWhereAPieceGoes(t *testing.T) {
	good := EchoFrame(EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, 1, []byte("x")))

	for _, tc := range []struct {
		name string
		fr   []byte
	}{
		{"first fragment", setFlags(good, 0x20, 0)},
		{"later fragment", setFlags(good, 0, 8)},
	} {
		dst, ok := ICMPFragment(tc.fr)
		if !ok {
			t.Errorf("%s was not seen as a piece of an ICMP datagram", tc.name)
			continue
		}
		if !dst.Equal(ipGW) {
			t.Errorf("%s names %s as its destination, want %s", tc.name, dst, ipGW)
		}
	}

	if _, ok := ICMPFragment(good); ok {
		t.Error("an intact echo reported as a fragment")
	}
	if _, ok := ICMPFragment(setProtocol(setFlags(good, 0x20, 0), 6)); ok {
		t.Error("a fragment of something else reported as an ICMP one")
	}
	if _, ok := ICMPFragment([]byte{1, 2, 3}); ok {
		t.Error("a runt reported as a fragment")
	}
}

// An ethertype of IPv4 with something else inside parses as nonsense IPv4, so
// the version nibble is checked too, as it is on the way in from the tunnel.
func TestIPv4InsideMustBeIPv4(t *testing.T) {
	good := EchoFrame(EchoRequest(macGuest, macGW, ipGuest, ipGW, 1, 1, []byte("x")))

	v6 := copyFrame(good)
	v6[14] = 6<<4 | 5

	if _, ok := ParseEcho(v6); ok {
		t.Error("an IPv6 header inside an IPv4 ethertype parsed as an echo")
	}
	if _, ok := Classify(v6); ok {
		t.Error("an IPv6 header inside an IPv4 ethertype classified as a flow")
	}
	if _, ok := ICMPFragment(setFlags(v6, 0x20, 0)); ok {
		t.Error("an IPv6 header inside an IPv4 ethertype seen as an ICMP fragment")
	}
}

// A frame whose sums do not add up is still described, but flagged as not
// adding up. These are the frames this gateway takes away from the stack and
// answers for itself, so for them the gateway is the receiver, and a receiver
// has to be able to tell what it is being handed.
func TestParseEchoReportsTheChecksums(t *testing.T) {
	req := EchoRequest(macGuest, macGW, ipGuest, ipGW, 7, 3, []byte("abcdefgh"))
	fr := EchoFrame(req)

	echo, ok := ParseEcho(fr)
	if !ok {
		t.Fatal("a frame this package builds is not readable by this package")
	}
	if !echo.ChecksumOK {
		t.Error("a frame built here does not add up, so the check itself is wrong")
	}

	// One bit in the payload: the ICMP message no longer sums.
	msg := copyFrame(fr)
	msg[len(msg)-1] ^= 0xff
	if echo, ok := ParseEcho(msg); !ok || echo.ChecksumOK {
		t.Error("a corrupted payload was reported as adding up")
	}

	// One bit in the IPv4 header, its checksum field untouched: the header no
	// longer sums, and the addresses the gateway would answer come out of it.
	ip := copyFrame(fr)
	ip[header.EthernetMinimumSize+8] ^= 0x01 // the time to live
	if echo, ok := ParseEcho(ip); !ok || echo.ChecksumOK {
		t.Error("a corrupted ipv4 header was reported as adding up")
	}
}
