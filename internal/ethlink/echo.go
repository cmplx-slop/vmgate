package ethlink

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// The two ICMP types an echo uses: a request, and the answer to it. Spelled
// from the netstack's constants, but kept under the names this package's
// callers use.
const (
	TypeEcho      = uint8(header.ICMPv4Echo)
	TypeEchoReply = uint8(header.ICMPv4EchoReply)
)

// Echo is one ICMP echo, the way it sits inside an ethernet frame.
type Echo struct {
	// The link and network addresses as they were seen: for a request from the
	// guest that is the guest's address and the gateway's MAC. Reverse turns
	// them around for the answer.
	SrcMAC, DstMAC net.HardwareAddr
	SrcIP, DstIP   net.IP

	// Type is TypeEcho or TypeEchoReply.
	Type uint8

	// Ident and Seq are the ping's identifier and sequence number. An answer
	// carries the pair from the request it answers, which is how the guest
	// knows which ping it was.
	Ident, Seq uint16

	// Payload is the ping's data, which an answer carries back unchanged.
	Payload []byte

	// ChecksumOK says both sums add up: the IPv4 header's and the ICMP
	// message's. A frame a device model built does; a frame put together by hand
	// need not, and the gateway declines to answer that one. It says nothing
	// about a frame built afterwards, Reverse included, whose sums are the
	// builder's own.
	ChecksumOK bool
}

// EchoRequest is an echo request with the addresses, identifier and sequence
// number asked for, ready for EchoFrame.
func EchoRequest(srcMAC, dstMAC net.HardwareAddr, src, dst net.IP, ident, seq uint16, payload []byte) Echo {
	return Echo{
		SrcMAC:  srcMAC,
		DstMAC:  dstMAC,
		SrcIP:   src,
		DstIP:   dst,
		Type:    TypeEcho,
		Ident:   ident,
		Seq:     seq,
		Payload: append([]byte(nil), payload...),
	}
}

// Reverse is the same echo travelling back the way it came, answering it:
// addresses and MACs swapped, request turned into answer, payload copied.
func (e Echo) Reverse() Echo {
	mac, ip := e.SrcMAC, e.SrcIP
	e.SrcMAC, e.DstMAC = e.DstMAC, mac
	e.SrcIP, e.DstIP = e.DstIP, ip
	if e.Type == TypeEcho {
		e.Type = TypeEchoReply
	} else {
		e.Type = TypeEcho
	}
	e.Payload = append([]byte(nil), e.Payload...)
	return e
}

// ParseEcho reports the echo request or answer carried by a frame, and says
// whether its two checksums add up.
//
// It looks through one VLAN tag, the same simplification Classify makes, and
// reads the ICMP message where the header length says it starts, so a frame with
// IP options is followed rather than refused. It does refuse frames that are
// fragmented or too short to hold a transport header: in a fragment there is no
// header to read.
//
// The sums are reported rather than acted on, because the caller is the one that
// has to decide. These are the frames the gateway takes away from the stack and
// answers itself, so for them the gateway is the receiver, and a receiver decides
// what it accepts; everything else goes to the stack, which was told this link
// offloads receive checksums and so checks nothing.
func ParseEcho(fr []byte) (Echo, bool) {
	pkt, ok := ipv4In(fr)
	if !ok {
		return Echo{}, false
	}
	ip := header.IPv4(pkt)
	if !ip.IsValid(len(pkt)) {
		return Echo{}, false
	}
	if !wholePacket(ip) {
		return Echo{}, false
	}
	if int(ip.Protocol()) != ProtoICMP {
		return Echo{}, false
	}
	// The ICMP message sits where the header length says, and the total length
	// says where it ends: an echo needs the eight header bytes and may carry any
	// amount of payload after them.
	msg := header.ICMPv4(pkt[ip.HeaderLength():ip.TotalLength()])
	if len(msg) < header.ICMPv4MinimumSize {
		return Echo{}, false
	}
	msgType := msg.Type()
	if msgType != header.ICMPv4Echo && msgType != header.ICMPv4EchoReply {
		return Echo{}, false
	}

	// Both sums, in the way the receiver checks them: summing the thing that was
	// sent, checksum field included, has to come to all ones. The header's own
	// sum matters as much as the message's here, because the addresses the
	// gateway answers are read out of that header.
	sums := ip.IsChecksumValid() && checksum.Checksum(msg, 0) == 0xffff

	eth := header.Ethernet(fr)
	return Echo{
		SrcMAC:  net.HardwareAddr(append([]byte(nil), eth.SourceAddress()...)),
		DstMAC:  net.HardwareAddr(append([]byte(nil), eth.DestinationAddress()...)),
		SrcIP:   ip4(ip.SourceAddress()),
		DstIP:   ip4(ip.DestinationAddress()),
		Type:    uint8(msgType),
		Ident:   msg.Ident(),
		Seq:     msg.Sequence(),
		Payload: append([]byte(nil), msg.Payload()...),

		ChecksumOK: sums,
	}, true
}

// EchoFrame is the ethernet frame carrying an echo, with the IPv4 and ICMP
// checksums calculated here. Addresses shorter than four bytes are read as
// zero, which only matters to a caller that forgot to check ParseEcho.
func EchoFrame(e Echo) []byte {
	icmpLen := header.ICMPv4MinimumSize + len(e.Payload)
	pkt := make([]byte, header.EthernetMinimumSize+header.IPv4MinimumSize+icmpLen)

	eth := header.Ethernet(pkt[:header.EthernetMinimumSize])
	eth.Encode(&header.EthernetFields{
		SrcAddr: tcpip.LinkAddress(e.SrcMAC),
		DstAddr: tcpip.LinkAddress(e.DstMAC),
		Type:    ethTypeIPv4,
	})

	src := tcpip.AddrFromSlice(v4(e.SrcIP))
	dst := tcpip.AddrFromSlice(v4(e.DstIP))
	ip := header.IPv4(pkt[header.EthernetMinimumSize:])
	ip.Encode(&header.IPv4Fields{
		TTL:         64,
		ID:          0,
		Protocol:    uint8(ProtoICMP),
		SrcAddr:     src,
		DstAddr:     dst,
		TotalLength: uint16(header.IPv4MinimumSize + icmpLen),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	msg := header.ICMPv4(pkt[header.EthernetMinimumSize+header.IPv4MinimumSize:])
	copy(msg.Payload(), e.Payload)
	msg.SetType(header.ICMPv4Type(e.Type))
	msg.SetCode(0)
	msg.SetIdent(e.Ident)
	msg.SetSequence(e.Seq)
	// An echo's checksum covers the ICMP message and nothing else: the pseudo
	// header belongs to TCP and UDP, and a checksum that wrongly includes it is
	// thrown away by the receiver. The checksum field is still zero, so the
	// whole message can be summed.
	msg.SetChecksum(^checksum.Checksum(msg, 0))

	return pkt
}

// v4 is the four bytes of an IPv4 address, or zeros for anything else.
func v4(ip net.IP) []byte {
	if v := ip.To4(); v != nil {
		return v
	}
	return []byte{0, 0, 0, 0}
}
