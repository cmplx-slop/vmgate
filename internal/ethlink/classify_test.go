package ethlink

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// buildFrame builds an ethernet frame carrying an IPv4 packet for proto, with the
// transport headers truncated to transport bytes.
func buildFrame(ethType uint16, proto int, src, dst string, transport []byte, ipOptions int) []byte {
	hdr := make([]byte, 14)
	copy(hdr, net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x02, 0x02})
	copy(hdr[6:], net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44})
	binary.BigEndian.PutUint16(hdr[12:], ethType)

	ihl := 5 + ipOptions
	ip := make([]byte, ihl*4)
	ip[0] = byte(4<<4 | ihl)
	total := len(ip) + len(transport)
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	ip[8] = 64
	ip[9] = byte(proto)
	copy(ip[12:16], net.ParseIP(src).To4())
	copy(ip[16:20], net.ParseIP(dst).To4())

	for i := 0; i < ipOptions; i++ {
		// A filler option: end of list, padded.
		ip[20+i*4] = 1
		ip[21+i*4] = 1
		ip[22+i*4] = 1
		ip[23+i*4] = 1
	}
	return append(hdr, append(ip, transport...)...)
}

// tcpSegment is a transport header with the ports and flags set.
func tcpSegment(srcPort, dstPort uint16, flags byte) []byte {
	seg := make([]byte, 20)
	binary.BigEndian.PutUint16(seg[0:], srcPort)
	binary.BigEndian.PutUint16(seg[2:], dstPort)
	seg[12] = 5 << 4
	seg[13] = flags
	return seg
}

func udpDatagram(srcPort, dstPort uint16) []byte {
	dg := make([]byte, 8)
	binary.BigEndian.PutUint16(dg[0:], srcPort)
	binary.BigEndian.PutUint16(dg[2:], dstPort)
	binary.BigEndian.PutUint16(dg[4:], 8)
	return dg
}

func TestClassifyTCP(t *testing.T) {
	const (
		syn    = 0x02
		synack = 0x12
	)

	for _, tc := range []struct {
		name          string
		flags         byte
		wantSYN       bool
		wantACK       bool
		wantOK        bool
		wantDstPort   uint16
		transportSize int
	}{
		{name: "syn", flags: syn, wantSYN: true, wantOK: true, wantDstPort: 80},
		{name: "syn-ack", flags: synack, wantSYN: true, wantACK: true, wantOK: true, wantDstPort: 80},
		{name: "data", flags: 0x18, wantACK: true, wantOK: true, wantDstPort: 80},
		// A frame that claims to carry TCP but stops after the ports is not a
		// flow the gateway can act on.
		{name: "truncated", transportSize: 4, wantOK: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := tcpSegment(5000, 80, tc.flags)
			if tc.transportSize > 0 {
				transport = transport[:tc.transportSize]
			}
			fr := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", transport, 0)

			got, ok := Classify(fr)
			if ok != tc.wantOK {
				t.Fatalf("Classify ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.SYN != tc.wantSYN || got.ACK != tc.wantACK {
				t.Errorf("flags = syn %v ack %v, want syn %v ack %v",
					got.SYN, got.ACK, tc.wantSYN, tc.wantACK)
			}
			if got.Proto != ProtoTCP {
				t.Errorf("proto = %d, want tcp", got.Proto)
			}
			if got.SrcPort != 5000 || got.DstPort != tc.wantDstPort {
				t.Errorf("ports = %d -> %d, want 5000 -> %d", got.SrcPort, got.DstPort, tc.wantDstPort)
			}
			if !got.SrcIP.Equal(net.ParseIP("10.0.2.15")) || !got.DstIP.Equal(net.ParseIP("1.1.1.1")) {
				t.Errorf("addresses = %s -> %s", got.SrcIP, got.DstIP)
			}
		})
	}
}

func TestClassifyUDP(t *testing.T) {
	fr := buildFrame(ethTypeIPv4, ProtoUDP, "10.0.2.15", "10.0.2.3", udpDatagram(40000, 53), 0)

	got, ok := Classify(fr)
	if !ok {
		t.Fatal("udp frame not classified")
	}
	if got.Proto != ProtoUDP {
		t.Errorf("proto = %d, want udp", got.Proto)
	}
	if got.SrcPort != 40000 || got.DstPort != 53 {
		t.Errorf("ports = %d -> %d, want 40000 -> 53", got.SrcPort, got.DstPort)
	}
	if got.SYN || got.ACK {
		t.Error("a datagram has no tcp flags")
	}
}

func TestClassifyVLANTagged(t *testing.T) {
	plain := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "8.8.8.8", tcpSegment(1, 443, 0x02), 0)

	tagged := make([]byte, 0, len(plain)+4)
	tagged = append(tagged, plain[:12]...)
	tagged = binary.BigEndian.AppendUint16(tagged, ethTypeVLAN)
	tagged = binary.BigEndian.AppendUint16(tagged, 100<<4) // VLAN id, priority zero
	tagged = append(tagged, plain[12:]...)

	got, ok := Classify(tagged)
	if !ok {
		t.Fatal("vlan tagged frame not classified")
	}
	if got.DstPort != 443 {
		t.Errorf("dst port = %d, want 443", got.DstPort)
	}
}

func TestClassifyIPOptions(t *testing.T) {
	// A 24 byte IP header: the transport header has to be found after it.
	fr := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(7, 80, 0x02), 1)

	got, ok := Classify(fr)
	if !ok {
		t.Fatal("frame with ip options not classified")
	}
	if got.SrcPort != 7 || got.DstPort != 80 {
		t.Errorf("ports = %d -> %d, want 7 -> 80", got.SrcPort, got.DstPort)
	}
	if !got.SYN {
		t.Error("syn flag lost")
	}
}

func TestClassifyRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		fr   []byte
	}{
		{"short", []byte{1, 2, 3}},
		{"arp", buildFrame(0x0806, ProtoTCP, "10.0.2.15", "10.0.2.2", tcpSegment(1, 2, 0x02), 0)},
		{"ipv6", buildFrame(0x86DD, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(1, 2, 0x02), 0)},
		{"icmp", buildFrame(ethTypeIPv4, 1, "10.0.2.15", "1.1.1.1", []byte{8, 0, 0, 0}, 0)},
		{"no transport", buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", nil, 0)},
		{"truncated ip", buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(1, 2, 0x02), 0)[:25]},
		{"ip header too short", func() []byte {
			fr := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(1, 2, 0x02), 0)
			fr[14] = 4<<4 | 4 // IHL below the minimum
			return fr
		}()},
		{"vlan tag cut short", func() []byte {
			fr := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(1, 2, 0x02), 0)
			out := append([]byte{}, fr[:12]...)
			return binary.BigEndian.AppendUint16(out, ethTypeVLAN)
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f, ok := Classify(tc.fr); ok {
				t.Fatalf("accepted %v", f)
			}
		})
	}
}

// The flow the gateway acts on must survive being handed out of the frame
// buffer: Classify must not alias the caller's memory.
func TestClassifyCopiesAddresses(t *testing.T) {
	fr := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "1.1.1.1", tcpSegment(1, 80, 0x02), 0)

	got, ok := Classify(fr)
	if !ok {
		t.Fatal("frame not classified")
	}
	before := append([]byte(nil), got.DstIP...)

	off := 14 + 16
	for i := range fr[off : off+4] {
		fr[off+i] = 0xFF
	}
	if !bytes.Equal(got.DstIP, before) {
		t.Errorf("dst address changed to %s when the frame was overwritten", got.DstIP)
	}
}

func TestClassifyRefusesFragments(t *testing.T) {
	good := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "198.51.100.7",
		tcpSegment(5000, 443, 0x02), 0)

	// A first fragment does carry the TCP header and a later one does not, but
	// neither says what the reassembled packet's ports are: the stack
	// reassembles and then asks for the real port, so a relay opened from a
	// fragment would sit unused while the flow the guest started found no
	// listener. Same rule ParseEcho applies.
	for _, tc := range []struct {
		name   string
		flags  uint8
		offset uint16
	}{
		{"first fragment", 0x20, 0},
		{"later fragment", 0, 8},
	} {
		if f, ok := Classify(setFlags(good, tc.flags, tc.offset)); ok {
			t.Errorf("%s classified as port %d -> %s:%d, want refused",
				tc.name, f.SrcPort, f.DstIP, f.DstPort)
		}
	}

	if _, ok := Classify(good); !ok {
		t.Error("an unfragmented segment stopped classifying")
	}
}

// A frame whose IPv4 total length disagrees with the bytes on the wire carries no
// flow, in either direction: shorter than its own header, or longer than the
// frame. The netstack drops such a packet before any socket sees it, so a relay
// opened from it would wait for a connection that can never arrive. Classify and
// ParseEcho apply the same rule the stack does, which is the point of reading the
// headers with the stack's own types.
func TestClassifyRefusesALyingTotalLength(t *testing.T) {
	good := buildFrame(ethTypeIPv4, ProtoTCP, "10.0.2.15", "198.51.100.7",
		tcpSegment(5000, 443, 0x02), 0)

	for _, total := range []int{1500, 15} {
		bad := append([]byte(nil), good...)
		binary.BigEndian.PutUint16(bad[14+2:], uint16(total))
		if _, ok := Classify(bad); ok {
			t.Errorf("total length %d classified as a flow, want refused", total)
		}
	}
}
