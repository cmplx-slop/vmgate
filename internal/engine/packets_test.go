package engine_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/dhcp"
	"vmgate/internal/dns"
	"vmgate/internal/qemu"
)

// ipFrame builds an ethernet frame carrying IPv4/UDP, the shape every DHCP
// packet arrives in. The UDP checksum is left zero, which IPv4 allows and
// which is what real DHCP clients do.
func ipFrame(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	const ethLen, ipLen, udpLen = 14, 20, 8
	total := ipLen + udpLen + len(payload)
	b := make([]byte, ethLen+total)

	// Ethernet: broadcast, because a client with no address has nobody to ask
	// unicast.
	for i := 0; i < 6; i++ {
		b[i] = 0xff
	}
	copy(b[6:], []byte{0x52, 0x54, 0x11, 0x22, 0x33, 0x44})
	binary.BigEndian.PutUint16(b[12:], 0x0800)

	ip := b[ethLen:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(total))
	ip[8] = 64 // TTL
	ip[9] = 17 // UDP
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	binary.BigEndian.PutUint16(ip[10:], checksum(ip[:ipLen]))

	udp := ip[ipLen:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(udpLen+len(payload)))
	copy(udp[udpLen:], payload)
	return b
}

// checksum computes the one's complement sum used by the IPv4 header.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// readDHCPFrame waits for one reply frame on the wire.
func readDHCPFrame(t *testing.T, peer *qemu.Stream) []byte {
	t.Helper()

	type result struct {
		fr  []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		fr, err := peer.ReadFrame()
		ch <- result{fr, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read reply frame: %v", r.err)
		}
		return r.fr
	case <-time.After(15 * time.Second):
		t.Fatal("no DHCP reply within 15s")
	}
	return nil
}

// readDHCP waits for one DHCP reply on the wire and decodes it.
func readDHCP(t *testing.T, peer *qemu.Stream) *dhcp.Message {
	t.Helper()

	return dhcpFromFrame(t, readDHCPFrame(t, peer))
}

// dhcpBytesFromFrame digs the DHCP message out of an ethernet frame: the
// payload of the UDP datagram, which is what a client reads.
func dhcpBytesFromFrame(t *testing.T, fr []byte) []byte {
	t.Helper()

	if len(fr) < 14 {
		t.Fatalf("short frame: %d bytes", len(fr))
	}
	eth := header.Ethernet(fr)
	if eth.Type() != header.IPv4ProtocolNumber {
		t.Fatalf("ethertype %#x, want ipv4", eth.Type())
	}
	ip := header.IPv4(fr[14:])
	if !ip.IsValid(len(fr) - 14) {
		t.Fatalf("invalid ipv4 header in %d byte frame", len(fr))
	}
	if ip.Protocol() != 17 {
		t.Fatalf("ip protocol = %d, want udp", ip.Protocol())
	}
	transport := fr[14+ip.HeaderLength():]
	if len(transport) < 8 {
		t.Fatalf("truncated udp header")
	}
	return transport[8:]
}

// dhcpFromFrame digs a DHCP message out of an ethernet qemu.
func dhcpFromFrame(t *testing.T, fr []byte) *dhcp.Message {
	t.Helper()

	msg, err := dhcp.Parse(dhcpBytesFromFrame(t, fr))
	if err != nil {
		t.Fatalf("parse dhcp message: %v", err)
	}
	return msg
}

// dhcpOptionUint16 reads a two byte option, such as the interface MTU, out of a
// reply, and fails the test when it is not there.
func dhcpOptionUint16(t *testing.T, m *dhcp.Message, code byte) int {
	t.Helper()

	for _, o := range m.Options {
		if o.Code != code {
			continue
		}
		if len(o.Value) != 2 {
			t.Fatalf("option %d is %d bytes, want 2", code, len(o.Value))
		}
		return int(binary.BigEndian.Uint16(o.Value))
	}
	t.Fatalf("option %d is missing from the reply", code)
	return 0
}

// dnsQuery builds the bytes of an A record query for name.
func dnsQuery(name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:], 0x4242) // id
	binary.BigEndian.PutUint16(b[4:], 1)      // QDCOUNT
	for _, label := range splitLabels(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, 0, dns.TypeA, 0, 0x01) // QTYPE=A QCLASS=IN
	return b
}

func splitLabels(name string) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				out = append(out, []byte(name[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, []byte(name[start:]))
	}
	return out
}

// dnsAnswers reports how many answers a reply carries and the last four bytes
// of the message, which for our synthetic answers is the A record's address.
func dnsAnswers(t *testing.T, reply []byte) (int, net.IP) {
	t.Helper()

	h, err := dns.ParseHeader(reply)
	if err != nil {
		t.Fatalf("parse reply: %v (% x)", err, reply)
	}
	if h.QDCount != 1 {
		t.Fatalf("questions = %d, want 1", h.QDCount)
	}
	if len(reply) < 4 {
		t.Fatalf("reply too short: %d bytes", len(reply))
	}
	return int(h.ANCount), net.IP(reply[len(reply)-4:])
}
