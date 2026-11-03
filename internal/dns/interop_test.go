package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A second opinion on the bytes this package writes.
//
// internal/dns hand-encodes replies. A reply here is the query's question with
// one record bolted on and nothing else changed, which is a decision about bytes
// rather than about a data structure, so it stays spelled out in dns.go. Reading
// a query is different: that is left to x/net/dns/dnsmessage, an implementation
// of the same RFCs by other people. The half that still needs a second opinion
// is the writing, and this file supplies it: a reply passes only if a parser
// nobody here wrote accepts it and reads back the same records. The queries in
// server_test.go are built from raw bytes for the same reason, so the parser the
// package now shares is checked against something that did not come from it.
//
// x/net is not a new module: this project already requires it, and the binary
// already links its ipv4, ipv6 and bpf packages for wireguard-go's raw sockets.

// The numbers this package's builders work with, named here rather than taken
// from dnsmessage so the assertions say what is on the wire.
const (
	typeA    = 1
	typeAAAA = 2
	classIN  = 1

	// answerTTL is the lifetime this package puts on a synthetic record. The
	// mapping is the operator's and can change between one lookup and the next,
	// so it is short.
	answerTTL = 60
)

// unpack decodes a message the way a client would, so a test can name what it
// expects instead of what the builder wrote.
func unpack(t *testing.T, msg []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(msg); err != nil {
		t.Fatalf("dnsmessage rejects the message: %v\nbytes: % x", err, msg)
	}
	return m
}

func TestBuildAnswerIsARealDNSReply(t *testing.T) {
	query := buildQuery("gateway.local", typeA)
	reply := BuildAnswer(query, net.IPv4(10, 0, 2, 2))

	m := unpack(t, reply)
	if !m.Response {
		t.Error("the reply does not have the response bit set")
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("rcode is %v, want success", m.RCode)
	}
	if m.ID != 0x1234 {
		t.Errorf("id is %#04x, want the query's 0x1234", m.ID)
	}
	if len(m.Questions) != 1 {
		t.Fatalf("%d questions, want the one the query asked", len(m.Questions))
	}
	want := dnsmessage.MustNewName("gateway.local.")
	if m.Questions[0].Name != want {
		t.Errorf("the reply asks for %q, want %q", m.Questions[0].Name.String(), want.String())
	}
	if m.Questions[0].Type != dnsmessage.TypeA || m.Questions[0].Class != dnsmessage.ClassINET {
		t.Errorf("the reply's question is %v/%v, want A/IN", m.Questions[0].Type, m.Questions[0].Class)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("%d answers, want one", len(m.Answers))
	}
	a, ok := m.Answers[0].Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("the answer is a %T, want an A record", m.Answers[0].Body)
	}
	if a.A != [4]byte{10, 0, 2, 2} {
		t.Errorf("the answer is %v, want 10.0.2.2", a.A)
	}
	if m.Answers[0].Header.Type != dnsmessage.TypeA || m.Answers[0].Header.Class != dnsmessage.ClassINET {
		t.Errorf("the answer's type and class are %v/%v, want A/IN",
			m.Answers[0].Header.Type, m.Answers[0].Header.Class)
	}
	if m.Answers[0].Header.TTL != answerTTL {
		t.Errorf("ttl is %d, want %d", m.Answers[0].Header.TTL, answerTTL)
	}
	// The name in the answer has to be the name that was asked for, which in a
	// real reply is a pointer back into the question rather than a second copy.
	if name := m.Answers[0].Header.Name; name != want {
		t.Errorf("the answer is for %q, want %q", name.String(), want.String())
	}
	// The reply has to claim no records it does not carry: a client that trusts
	// the header counts would read past the end otherwise.
	if len(m.Authorities) != 0 || len(m.Additionals) != 0 {
		t.Errorf("the reply carries %d authority and %d additional records, want none",
			len(m.Authorities), len(m.Additionals))
	}
}

// The builder hangs its answer off the end of the query, so the counts in the
// header are a promise the rest of the message has to keep. dnsmessage reads the
// sections by those counts, which makes it the test of whether the promise holds:
// a count that is too high makes it read past what is there, and one that is too
// low moves a record into a section nobody asked for.
func TestReplyCountsMatchWhatFollows(t *testing.T) {
	cases := []struct {
		name    string
		reply   []byte
		answers int
		rcode   dnsmessage.RCode
	}{
		{"answer", BuildAnswer(buildQuery("gateway.local", typeA), net.IPv4(10, 0, 2, 2)), 1, dnsmessage.RCodeSuccess},
		{"no answer", noAnswerTo(buildQuery("gateway.local", typeAAAA)), 0, dnsmessage.RCodeSuccess},
		{"name error", BuildNXDomain(buildQuery("nowhere.invalid", typeA)), 0, dnsmessage.RCodeNameError},
	}
	for _, tc := range cases {
		m := unpack(t, tc.reply)
		if m.RCode != tc.rcode {
			t.Errorf("%s: rcode %v, want %v", tc.name, m.RCode, tc.rcode)
		}
		if len(m.Questions) != 1 {
			t.Errorf("%s: %d questions, want the query's one", tc.name, len(m.Questions))
		}
		if len(m.Answers) != tc.answers {
			t.Errorf("%s: the parser read %d answers, want %d", tc.name, len(m.Answers), tc.answers)
		}
		if len(m.Authorities) != 0 || len(m.Additionals) != 0 {
			t.Errorf("%s: %d authority and %d additional records, want none",
				tc.name, len(m.Authorities), len(m.Additionals))
		}
	}
}

// The queries this package's other tests hand-build are a guess at what a client
// sends. Here a query comes from another implementation instead, and the question
// is whether our parser reads it as its author meant.
func TestParseQuestionReadsWhatAnotherImplementationWrites(t *testing.T) {
	names := []string{"example.com", "a", strings.Repeat("l", 63), "x.y.z.w", "gateway.local"}
	for _, name := range names {
		msg := buildQuery(name, typeA)

		q, err := ParseQuestion(msg)
		if err != nil {
			t.Fatalf("ParseQuestion refuses a query dnsmessage wrote (%q): %v", name, err)
		}
		if !strings.EqualFold(q.Name, name) {
			t.Errorf("ParseQuestion read %q from a query for %q", q.Name, name)
		}
		if q.Type != typeA || q.Class != classIN {
			t.Errorf("ParseQuestion read type %d class %d, want A/IN", q.Type, q.Class)
		}
		// A query written by someone else has to be answerable, and the answer
		// has to carry that query's question back. The builder does that from
		// what it parsed rather than by copying bytes, so the check here is on
		// the query as it arrived: one question record and nothing after it.
		if end := scanQuestion(t, msg); end != len(msg) {
			t.Errorf("the question record ends at %d in a %d byte query, want the end", end, len(msg))
		}
	}
}

// A reply has to answer the question it was given, even when the query is not the
// ordinary one: the id and the bits the client asked with survive the splice.
func TestBuilderFollowsAnUnusualQuery(t *testing.T) {
	// A query asking for recursion, with a name long enough to be worth
	// compressing, and an id that is not the test's usual one.
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:               0xbeef,
		RecursionDesired: true,
	})
	if err := b.StartQuestions(); err != nil {
		t.Fatalf("dnsmessage could not start the question: %v", err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatalf("dnsmessage could not write the question: %v", err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatalf("dnsmessage could not finish the query: %v", err)
	}

	reply := BuildAnswer(msg, net.IPv4(198, 51, 100, 5))
	m := unpack(t, reply)
	if m.ID != 0xbeef {
		t.Errorf("id is %#04x, want the query's 0xbeef", m.ID)
	}
	if !m.RecursionDesired {
		t.Error("the reply dropped the recursion-desired bit the query asked with")
	}
	if len(m.Questions) != 1 || !strings.EqualFold(m.Questions[0].Name.String(), "www.example.com.") {
		t.Errorf("the reply's question is %v, want www.example.com.", m.Questions[0].Name)
	}
	if len(m.Answers) != 1 {
		t.Fatalf("%d answers, want one", len(m.Answers))
	}
	if !strings.EqualFold(m.Answers[0].Header.Name.String(), "www.example.com.") {
		t.Errorf("the answer is for %q, want the name that was asked", m.Answers[0].Header.Name.String())
	}
}

// What the gateway does with a message that is not quite right, written down
// rather than left to be discovered: refuse is what this package has to do, and
// want is the name it has to read when it does not refuse. The reading is
// dnsmessage's, so the table is also a record of what that means here. The other
// column says what dnsmessage does when asked to unpack the whole message, which
// is what a client would make of the same bytes, because a rule that moves
// silently is worse than no test at all.
func TestBrokenQueriesAreRefusedOrUnderstood(t *testing.T) {
	cases := []struct {
		name string
		msg  []byte

		// refuse is what our parser has to do with the message; want is the name
		// it has to read when it does not refuse.
		refuse bool
		want   string

		// other records what dnsmessage does: true when it accepts the message.
		other bool
	}{
		{
			name:   "no question at all",
			msg:    headerOnly(),
			refuse: true,
			// A header with nothing in it is a well formed empty message to
			// dnsmessage; this package has no question to answer, so it says so.
			other: true,
		},
		{
			name:   "name runs past the message",
			msg:    []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'l', 'o', 'n', 'g'},
			refuse: true,
			other:  false,
		},
		{
			// dnsmessage presents the root as ".", and this package strips the
			// trailing root dot off every name it hands on, because that is the
			// form the operator writes and the form AddHost reduces a configured
			// name to. A query for the root is therefore a query with no name
			// here, and it is relayed upstream or answered from dns.map_hosts
			// exactly as a query for any other name is.
			name:   "a query for the root",
			msg:    []byte{0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1},
			refuse: false,
			want:   "",
			other:  true,
		},
		{
			// A label longer than the 63 bytes RFC 1035 allows is refused here.
			// The name walker this package wrote for itself checked no length
			// limit at all, so an over-long label came out as whatever the walk
			// happened to land on; refusing it means the guest's resolver retries
			// rather than being answered for a name no one could register.
			name:   "a label longer than the RFC allows",
			msg:    oneLabelQuery(strings.Repeat("l", 64)),
			refuse: true,
			other:  false,
		},
	}
	for _, tc := range cases {
		got, err := ParseQuestion(tc.msg)
		switch {
		case tc.refuse && err == nil:
			t.Errorf("%s: our parser read %q, want it refused", tc.name, got.Name)
		case !tc.refuse && err != nil:
			t.Errorf("%s: our parser refused where dnsmessage accepts: %v", tc.name, err)
		case !tc.refuse && got.Name != tc.want:
			t.Errorf("%s: our parser read %q, want %q", tc.name, got.Name, tc.want)
		}

		var m dnsmessage.Message
		derr := m.Unpack(tc.msg)
		if (derr == nil) != tc.other {
			t.Errorf("%s: dnsmessage now does something else than this test records (err: %v)", tc.name, derr)
		}
	}
}

// buildQuery is the one question A query the other tests in this file need, with
// a known id, built by dnsmessage rather than by hand.
func buildQuery(name string, qtype uint16) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		panic("dns: could not start a test query: " + err.Error())
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(makeCanonical(name)),
		Type:  dnsmessage.Type(qtype),
		Class: dnsmessage.ClassINET,
	}); err != nil {
		panic("dns: could not write a test query for " + name + ": " + err.Error())
	}
	msg, err := b.Finish()
	if err != nil {
		panic("dns: could not finish a test query for " + name + ": " + err.Error())
	}
	return msg
}

// headerOnly is a DNS message with a header and no question.
func headerOnly() []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
	msg, err := b.Finish()
	if err != nil {
		panic("dns: could not build a test header: " + err.Error())
	}
	return msg
}

// makeCanonical turns "example.com" into the presentation form dnsmessage wants,
// which is the name with its trailing root dot: "example.com.".
func makeCanonical(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

// oneLabelQuery is a one question A query for a single label, written out byte by
// byte rather than by dnsmessage, so that the odd cases below start from bytes a
// client could put on the wire.
func oneLabelQuery(label string) []byte {
	msg := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, byte(len(label))}
	msg = append(msg, label...)
	msg = append(msg, 0, 0, typeA, 0, classIN)
	return msg
}

// A name may hold compression pointers, which is how the answer and authority
// sections of a real reply save space. A question has nothing earlier to point
// at, so a pointer there comes from a confused or a hostile client. These are the
// three shapes and what this package makes of each. One of them is a change from
// the name walker this package wrote for itself: a pointer that leads back into
// the same name used to be answered as the part read before the loop, so a guest
// could ask for a name no client would have written. It is refused now, along
// with any name that leans on more than ten pointers.
func TestCompressionPointersInAQuestion(t *testing.T) {
	cases := []struct {
		name   string
		msg    []byte
		refuse bool
		want   string
		qtype  uint16
	}{
		{
			// The name ends with its root label, so the pointer sits where the
			// question type is, and is read as one: 0xC00C, a type nobody uses.
			name:  "pointer after a finished name",
			msg:   append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 3, 'g', 'a', 't', 7, 'h', 'e', 'r', 'l', 'o', 'c', 'a', 0, 0xC0, 0x0C, 0, typeA, 0, classIN),
			want:  "gat.herloca",
			qtype: 0xC00C,
		},
		{
			// The name is still going when the pointer comes, and it points at
			// the start of the name it is inside.
			name:   "pointer back into its own name",
			msg:    append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 3, 'g', 'a', 't', 0xC0, 0x0C, 0, typeA, 0, classIN),
			refuse: true,
		},
		{
			// A pointer to somewhere past the question, which is where a
			// compressed name would have to have been written first: it was not.
			name:  "pointer past the question",
			msg:   append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 3, 'w', 'w', 'w', 0xC0, 0x14, 0, typeA, 0, classIN),
			want:  "www",
			qtype: typeA,
		},
	}
	for _, tc := range cases {
		q, err := ParseQuestion(tc.msg)
		switch {
		case tc.refuse && err == nil:
			t.Errorf("%s: read %q, want it refused", tc.name, q.Name)
		case !tc.refuse && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case !tc.refuse:
			if q.Name != tc.want {
				t.Errorf("%s: name is %q, want %q", tc.name, q.Name, tc.want)
			}
			if q.Type != tc.qtype {
				t.Errorf("%s: type is %d, want %d", tc.name, q.Type, tc.qtype)
			}
		}
	}
}

// A query may advertise a receive buffer with an EDNS0 OPT record. The reply does
// not repeat it: the gateway answers through a tunnel whose MTU is smaller than
// most resolvers' buffers, and an OPT inviting a larger answer would ask for one
// that has to be fragmented. Whatever else the query carried after its question
// is left off, which is what the record counts say.
func TestReplyCarriesNoEDNSOpt(t *testing.T) {
	msg := buildQuery("gateway.local", typeA)
	// An OPT record by hand: root name, type 41, a 4096 byte buffer, and no
	// options of its own.
	msg = append(msg, 0, 0, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(msg[10:], 1)

	h, err := ParseHeader(msg)
	if err != nil {
		t.Fatal(err)
	}
	if h.ARCount != 1 {
		t.Fatalf("the test query carries %d additional records, want one", h.ARCount)
	}

	reply := BuildAnswer(msg, net.IPv4(10, 0, 2, 2))
	rh, err := ParseHeader(reply)
	if err != nil {
		t.Fatal(err)
	}
	if rh.ARCount != 0 {
		t.Errorf("the reply advertises %d additional records, want none", rh.ARCount)
	}
	m := unpack(t, reply)
	if len(m.Additionals) != 0 {
		t.Errorf("dnsmessage reads %d additional records in the reply, want none", len(m.Additionals))
	}
	if len(m.Questions) != 1 {
		t.Fatalf("%d questions, want the query's one", len(m.Questions))
	}
	if len(m.Answers) != 1 {
		t.Fatalf("%d answers, want one", len(m.Answers))
	}
}
