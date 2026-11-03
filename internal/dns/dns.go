package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// messageHeader is a DNS message header.
type messageHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const minLen = 12

// ParseHeader decodes the fixed part of a DNS message.
//
// This stays hand written although dnsmessage is used for the rest of the
// message, because what it reads is what this package writes by hand: the record
// counts. dnsmessage's own header has no counts at all, since it takes them from
// the sections it is given, so checking a reply's counts against its records
// needs a reader that sees the bytes.
func ParseHeader(msg []byte) (messageHeader, error) {
	if len(msg) < minLen {
		return messageHeader{}, fmt.Errorf("dns: short message (%d bytes)", len(msg))
	}
	return messageHeader{
		ID:      binary.BigEndian.Uint16(msg[0:]),
		Flags:   binary.BigEndian.Uint16(msg[2:]),
		QDCount: binary.BigEndian.Uint16(msg[4:]),
		ANCount: binary.BigEndian.Uint16(msg[6:]),
		NSCount: binary.BigEndian.Uint16(msg[8:]),
		ARCount: binary.BigEndian.Uint16(msg[10:]),
	}, nil
}

// question is everything this package needs from a query: the question record,
// which a reply has to carry back unchanged, and the two message fields a reply
// answers with.
type question struct {
	Name  string
	Type  uint16
	Class uint16

	// wire is the same question in the form dnsmessage writes a name in, which
	// is how a reply gets the question back without anyone walking the labels a
	// second time.
	wire dnsmessage.Question

	// id and rd are the query's message id and its recursion-desired bit.
	id uint16
	rd bool
}

// ParseQuestion decodes the first question of a DNS message.
func ParseQuestion(msg []byte) (question, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return question{}, fmt.Errorf("dns: header: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		// A message with no question in it comes here as well: the parser takes
		// the question count from the header and reports the section as already
		// finished. There is nothing to answer, which is a refusal rather than
		// an empty name.
		return question{}, fmt.Errorf("dns: no question to answer: %w", err)
	}
	return question{
		// dnsmessage presents a name as a fully qualified one, with the root
		// label written as a trailing dot. The names this package works with are
		// the form the operator writes, without it, which is also what AddHost
		// reduces a configured name to; a query for the root is therefore a query
		// with no name, which is how it is treated.
		Name:  strings.TrimSuffix(q.Name.String(), "."),
		Type:  uint16(q.Type),
		Class: uint16(q.Class),
		wire:  q,
		id:    h.ID,
		rd:    h.RecursionDesired,
	}, nil
}

// TypeA is the DNS A record type.
const TypeA = 1

// replyHead writes the header and the question record of a reply: the query's id
// and recursion bit, the response bit, the return code, and the question carried
// back as it was asked. Everything the query had after its question is left off,
// which includes any EDNS0 record it arrived with: the gateway advertises no
// larger buffer than the tunnel it answers through.
func (q *question) replyHead(answers, rcode int) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               q.id,
		Response:         true,
		RecursionDesired: q.rd,
		RCode:            dnsmessage.RCode(rcode),
	})
	if err := b.StartQuestions(); err != nil {
		return nil
	}
	if err := b.Question(q.wire); err != nil {
		return nil
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	// The builder has counted the one question it wrote and no records, because
	// no records went through it: the answer records are appended by hand after
	// this, so their count is written here.
	binary.BigEndian.PutUint16(out[6:], uint16(answers))
	return out
}

// answer builds a one-answer response to a query, carrying the given IPv4
// address. A non-IPv4 address, including nil, is a name the gateway knows but
// has no answer for, which is the same reply as an empty one.
func (q *question) answer(ip net.IP) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return q.noAnswer()
	}
	out := q.replyHead(1, 0)
	if out == nil {
		return nil
	}
	// The answer's name is a pointer back to the question at offset 12.
	out = append(out, 0xC0, 0x0C)
	out = append(out, 0x00, TypeA, 0x00, 0x01) // TYPE=A CLASS=IN
	out = append(out, 0, 0, 0, 60)             // TTL 60s
	out = append(out, 0, 4)
	out = append(out, v4...)
	return out
}

// noAnswer replies with NOERROR but no records, used for names the gateway knows
// but cannot answer with the requested type.
func (q *question) noAnswer() []byte {
	return q.replyHead(0, 0)
}

// nxdomain replies that the name does not exist.
func (q *question) nxdomain() []byte {
	return q.replyHead(0, 3)
}

// BuildAnswer is answer for a caller holding a query's bytes rather than a parsed
// question.
func BuildAnswer(msg []byte, ip net.IP) []byte {
	q, err := ParseQuestion(msg)
	if err != nil {
		return nil
	}
	return q.answer(ip)
}

// BuildNXDomain is nxdomain for a caller holding a query's bytes.
func BuildNXDomain(msg []byte) []byte {
	q, err := ParseQuestion(msg)
	if err != nil {
		return nil
	}
	return q.nxdomain()
}
