// Package dhcp implements just enough of RFC 2131 to hand a guest an
// address, a gateway and a resolver. It deliberately has no dependency on
// the networking stack: the server talks to an abstract Conn, which makes it
// easy to unit test with synthetic packets.
package dhcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Message operations.
const (
	OpBootpRequest = 1
	OpBootpReply   = 2
)

// DHCP message types (option 53).
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	Ack      = 5
	Nak      = 6
	Release  = 7
	Inform   = 8
)

// Option codes.
const (
	OptPad          = 0
	OptSubnetMask   = 1
	OptTimeOffset   = 2
	OptRouter       = 3
	OptNameServer   = 5
	OptDNS          = 6
	OptHostname     = 12
	OptFileSize     = 13
	OptDomainName   = 15
	OptInterfaceMTU = 26
	OptRequestedIP  = 50
	OptLeaseTime    = 51
	OptOverload     = 52
	OptMessageType  = 53
	OptServerID     = 54
	OptParamRequest = 55
	OptRenewalTime  = 58
	OptRebindTime   = 59
	OptEnd          = 255
)

// Flags.
const FlagBroadcast = 0x8000

// Sizes of the fixed BOOTP fields.
const (
	fixedSize  = 236
	nameSize   = 64
	bootFile   = 128
	chaddrSize = 16
)

const (
	// magicCookie is the four bytes at the front of the BOOTP vendor area that
	// say "the options after me are DHCP options" (RFC 1048, RFC 2131): the
	// address 99.130.83.99, that is 0x63 0x82 0x53 0x63. Both directions have
	// to get these bytes exactly right. A client's request without them is not
	// DHCP and gets no answer, and a reply carrying anything else is a reply
	// no client will read: dhclient says "malformed packet" and never gets as
	// far as the options.
	magicCookie = 0x63825363

	// minLen is the fixed part plus the magic cookie: the shortest message
	// that can carry anything at all.
	minLen = fixedSize + 4
)

var (
	// ErrShort reports a truncated message.
	ErrShort = errors.New("dhcp: message too short")

	// ErrCookie reports a missing magic cookie.
	ErrCookie = errors.New("dhcp: bad magic cookie")
)

// Message is a decoded BOOTP/DHCP message.
type Message struct {
	Op       byte
	HType    byte
	HLen     byte
	Hops     byte
	XID      uint32
	Secs     uint16
	Flags    uint16
	ClientIP net.IP
	YourIP   net.IP
	ServerIP net.IP
	RelayIP  net.IP
	CHAddr   []byte
	SName    string
	BootFile string
	Options  Options
}

// HardwareAddress returns the client MAC address.
func (m *Message) HardwareAddress() net.HardwareAddr {
	n := int(m.HLen)
	if n > len(m.CHAddr) {
		n = len(m.CHAddr)
	}
	return net.HardwareAddr(m.CHAddr[:n])
}

// Type returns the DHCP message type, or DISCOVER for a client that omits
// it (some firmware does that for its first REQUEST), so callers never have
// to know that the option can be missing.
func (m *Message) Type() byte {
	if v, ok := m.Options.Get(OptMessageType); ok && len(v) > 0 {
		return v[0]
	}
	return 0
}

// Parse decodes a BOOTP/DHCP message.
func Parse(b []byte) (*Message, error) {
	if len(b) < minLen {
		return nil, ErrShort
	}
	m := &Message{
		Op:       b[0],
		HType:    b[1],
		HLen:     b[2],
		Hops:     b[3],
		XID:      binary.BigEndian.Uint32(b[4:8]),
		Secs:     binary.BigEndian.Uint16(b[8:10]),
		Flags:    binary.BigEndian.Uint16(b[10:12]),
		ClientIP: net.IP(b[12:16]),
		YourIP:   net.IP(b[16:20]),
		ServerIP: net.IP(b[20:24]),
		RelayIP:  net.IP(b[24:28]),
	}
	n := int(m.HLen)
	if n > chaddrSize {
		n = chaddrSize
	}
	m.CHAddr = append([]byte(nil), b[28:28+n]...)
	m.SName = cstring(b[44 : 44+nameSize])
	m.BootFile = cstring(b[44+nameSize : fixedSize])

	if binary.BigEndian.Uint32(b[fixedSize:fixedSize+4]) != magicCookie {
		return nil, ErrCookie
	}
	opts := b[fixedSize+4:]
	for i := 0; i < len(opts); {
		code := opts[i]
		if code == OptEnd {
			break
		}
		if code == OptPad {
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		m.Options = append(m.Options, Option{Code: code, Value: append([]byte(nil), opts[i+2:i+2+l]...)})
		i += 2 + l
	}
	return m, nil
}

// Marshal encodes the message, padded to the 300 byte BOOTP minimum.
func (m *Message) Marshal() []byte {
	hlen := len(m.CHAddr)
	if hlen > chaddrSize {
		hlen = chaddrSize
	}
	buf := make([]byte, fixedSize+4)
	buf[0] = m.Op
	buf[1] = m.HType
	if m.HType == 0 {
		buf[1] = 1 // ethernet
	}
	buf[2] = byte(hlen)
	if buf[2] == 0 {
		buf[2] = 6
	}
	buf[3] = m.Hops
	binary.BigEndian.PutUint32(buf[4:8], m.XID)
	binary.BigEndian.PutUint16(buf[8:10], m.Secs)
	binary.BigEndian.PutUint16(buf[10:12], m.Flags)
	copy(buf[12:16], ip4(m.ClientIP))
	copy(buf[16:20], ip4(m.YourIP))
	copy(buf[20:24], ip4(m.ServerIP))
	copy(buf[24:28], ip4(m.RelayIP))
	copy(buf[28:28+hlen], m.CHAddr[:hlen])
	copy(buf[44:44+nameSize], m.SName)
	copy(buf[44+nameSize:fixedSize], m.BootFile)
	binary.BigEndian.PutUint32(buf[fixedSize:fixedSize+4], magicCookie)

	for _, opt := range m.Options {
		if len(opt.Value) > 255 {
			continue
		}
		buf = append(buf, opt.Code, byte(len(opt.Value)))
		buf = append(buf, opt.Value...)
	}
	buf = append(buf, OptEnd)
	// Pad up to the traditional minimum length so that picky clients, which
	// expect a full 300 byte frame, stay happy.
	for len(buf) < 300 {
		buf = append(buf, OptPad)
	}
	return buf
}

// TypeString renders a message type for logs.
func TypeString(t byte) string {
	switch t {
	case Discover:
		return "DISCOVER"
	case Offer:
		return "OFFER"
	case Request:
		return "REQUEST"
	case Decline:
		return "DECLINE"
	case Ack:
		return "ACK"
	case Nak:
		return "NAK"
	case Release:
		return "RELEASE"
	case Inform:
		return "INFORM"
	default:
		return fmt.Sprintf("type(%d)", t)
	}
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
