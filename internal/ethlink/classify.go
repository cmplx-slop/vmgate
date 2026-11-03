package ethlink

import (
	"encoding/binary"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// Transport protocols recognised by Classify, taken from the netstack's own
// numbers so the two cannot drift. ProtoICMP is not a flow: the gateway answers
// echo itself, at the frame level, and ParseEcho reads those.
const (
	ProtoNone = 0
	ProtoTCP  = int(header.TCPProtocolNumber)
	ProtoUDP  = int(header.UDPProtocolNumber)
	ProtoICMP = int(header.ICMPv4ProtocolNumber)
)

// Ethertypes the link has to know. The netstack's header package defines the
// ethernet wrapper but not these two numbers, so they stay here.
const (
	ethTypeVLAN = 0x8100
	ethTypeIPv4 = 0x0800
)

// Flow identifies the transport-level endpoints of an ethernet frame. The
// gateway uses it to decide which on-demand listener to open when
// gateway.internet mode must accept a connection to an address the stack does
// not own yet.
type Flow struct {
	Proto   int
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16

	// SYN and ACK carry TCP flags and are false for other protocols. The
	// gateway only opens listeners for frames that start a connection.
	SYN bool
	ACK bool
}

// Classify parses an ethernet frame and reports the flow it carries. The
// second return value is false when the frame does not carry IPv4 TCP or UDP.
//
// Everything it reads comes from the netstack's own header types: a frame this
// function understands is a frame the stack behind it can understand, which is
// the property the gateway depends on.
func Classify(fr []byte) (Flow, bool) {
	pkt, ok := ipv4In(fr)
	if !ok {
		return Flow{}, false
	}
	ip := header.IPv4(pkt)
	// The netstack's own sanity check: header length within the packet, total
	// length within the packet, and a header that says IPv4.
	if !ip.IsValid(len(pkt)) {
		return Flow{}, false
	}
	if isFragment(ip) {
		// A fragment carries no transport header, so the port it appears to
		// carry is whatever the payload happens to begin with. The stack
		// reassembles the real packet, which then asks for its real port: a
		// relay opened from a fragment would sit unused while the flow the
		// guest started found no listener at all.
		return Flow{}, false
	}
	proto := int(ip.Protocol())
	transport := pkt[ip.HeaderLength():]
	switch proto {
	case ProtoTCP:
		if len(transport) < header.TCPMinimumSize {
			return Flow{}, false
		}
		tcp := header.TCP(transport)
		flags := tcp.Flags()
		return Flow{
			Proto:   proto,
			SrcIP:   ip4(ip.SourceAddress()),
			DstIP:   ip4(ip.DestinationAddress()),
			SrcPort: tcp.SourcePort(),
			DstPort: tcp.DestinationPort(),
			SYN:     flags.Intersects(header.TCPFlagSyn),
			ACK:     flags.Intersects(header.TCPFlagAck),
		}, true
	case ProtoUDP:
		if len(transport) < header.UDPMinimumSize {
			return Flow{}, false
		}
		udp := header.UDP(transport)
		return Flow{
			Proto:   proto,
			SrcIP:   ip4(ip.SourceAddress()),
			DstIP:   ip4(ip.DestinationAddress()),
			SrcPort: udp.SourcePort(),
			DstPort: udp.DestinationPort(),
		}, true
	default:
		return Flow{}, false
	}
}

// isFragment reports whether an IPv4 packet is one piece of a larger datagram.
// Only the first piece holds the transport header, so nothing in a later piece
// can be read; and the netstack behind this gateway does reassemble, so a
// fragment cannot be waved through as "nothing to see here" either: what the
// stack makes of it is a decision the frame hook has to take. Manager.Inspect
// explains what it decides for ICMP.
func isFragment(ip header.IPv4) bool {
	return ip.More() || ip.FragmentOffset() != 0
}

// wholePacket is the other way round: a packet that is whole, and so the only
// kind whose transport header is readable. ParseEcho and Classify both refuse
// anything else.
func wholePacket(ip header.IPv4) bool { return !isFragment(ip) }

// ICMPFragment reports that a frame carries a fragment of an ICMP datagram, and
// returns the destination address the fragment names. It exists because the
// question "is this ICMP?" cannot be answered from a fragment: the ICMP header
// is in the first piece only, and this gateway does not reassemble. A caller
// that wants to know whether the stack may see such a frame has to ask it
// without the header, which is what this says.
func ICMPFragment(fr []byte) (net.IP, bool) {
	pkt, ok := ipv4In(fr)
	if !ok {
		return nil, false
	}
	ip := header.IPv4(pkt)
	if int(ip.Protocol()) != ProtoICMP || !isFragment(ip) {
		return nil, false
	}
	return ip4(ip.DestinationAddress()), true
}

// ipv4In is the IPv4 packet inside an ethernet frame, looking through a single
// VLAN tag if there is one. The second value is false when the frame carries
// nothing that could be IPv4.
func ipv4In(fr []byte) ([]byte, bool) {
	if len(fr) < header.EthernetMinimumSize {
		return nil, false
	}
	ethType := uint16(header.Ethernet(fr).Type())
	pkt := fr[header.EthernetMinimumSize:]
	if ethType == ethTypeVLAN {
		if len(fr) < header.EthernetMinimumSize+4 {
			return nil, false
		}
		ethType = binary.BigEndian.Uint16(fr[header.EthernetMinimumSize+2:])
		pkt = fr[header.EthernetMinimumSize+4:]
	}
	// The version nibble is checked as well as the ethertype, because a frame
	// that claims to carry IPv4 and holds something else parses as nonsense
	// IPv4. The tunnel's shim applies the same rule on the way in from the
	// peer, and it is worth one comparison to keep the two sides as strict as
	// each other.
	if ethType != ethTypeIPv4 || len(pkt) < header.IPv4MinimumSize || header.IPVersion(pkt) != header.IPv4Version {
		return nil, false
	}
	return pkt, true
}

// ethertype reports the protocol carried by a frame, following a single VLAN
// tag if there is one. It is only used for reporting and logging: the ethernet
// wrapper re-reads it from the frame when the packet is delivered.
func ethertype(fr []byte) tcpip.NetworkProtocolNumber {
	if len(fr) < header.EthernetMinimumSize {
		return 0
	}
	typ := header.Ethernet(fr).Type()
	if typ == ethTypeVLAN && len(fr) >= header.EthernetMinimumSize+4 {
		typ = tcpip.NetworkProtocolNumber(binary.BigEndian.Uint16(fr[header.EthernetMinimumSize+2:]))
	}
	return typ
}

// ip4 is a netstack address as a net.IP, copied so it never aliases the frame it
// was read from.
func ip4(a tcpip.Address) net.IP {
	return net.IP(append([]byte(nil), a.AsSlice()...))
}
