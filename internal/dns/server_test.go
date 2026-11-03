package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// query builds a one question DNS message.
func query(name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:], 0x1234) // id
	binary.BigEndian.PutUint16(msg[4:], 1)      // qdcount
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	return binary.BigEndian.AppendUint16(msg, 1) // class IN
}

// noAnswerTo is what the gateway replies to a query for a name it knows with a
// type it does not: NOERROR and no records. It goes through the parsed question,
// which is how the server itself answers.
func noAnswerTo(msg []byte) []byte {
	q, err := ParseQuestion(msg)
	if err != nil {
		panic("dns: test query cannot be parsed: " + err.Error())
	}
	return q.noAnswer()
}

// scanQuestion finds where the first question record of a message ends.
//
// The package itself no longer walks names by hand, so a test that wants to know
// where a reply's question stops cannot ask it. This is a second, deliberately
// separate implementation of the walk: it only handles the uncompressed names
// the tests write, which is enough to check the bytes those tests get back.
func scanQuestion(t *testing.T, msg []byte) int {
	t.Helper()

	off := 12
	for off < len(msg) {
		l := int(msg[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			t.Fatal("scanQuestion only walks uncompressed names, as the tests write them")
		}
		off += 1 + l
	}
	if off+4 > len(msg) {
		t.Fatalf("question record runs off the end of a %d byte message", len(msg))
	}
	return off + 4 // the name, then the type and class it asks about
}

// firstAnswer pulls the address out of the first answer record of a response.
func firstAnswer(t *testing.T, msg []byte) net.IP {
	t.Helper()

	h, err := ParseHeader(msg)
	if err != nil {
		t.Fatal(err)
	}
	if h.ANCount == 0 {
		t.Fatalf("response has no answers: %v", h)
	}

	off := scanQuestion(t, msg)
	if off+10 > len(msg) {
		t.Fatalf("answer record truncated at %d", off)
	}
	if msg[off]&0xC0 != 0xC0 {
		t.Errorf("answer name is not a pointer: %#x", msg[off])
	}
	off += 2
	if got := binary.BigEndian.Uint16(msg[off:]); got != TypeA {
		t.Errorf("answer type = %d, want A", got)
	}
	off += 2
	if got := binary.BigEndian.Uint16(msg[off:]); got != 1 {
		t.Errorf("answer class = %d, want IN", got)
	}
	off += 6 // class + ttl
	rdlen := binary.BigEndian.Uint16(msg[off:])
	off += 2
	if rdlen != 4 {
		t.Fatalf("answer rdlength = %d, want 4", rdlen)
	}
	if off+4 > len(msg) {
		t.Fatal("answer rdata truncated")
	}
	return net.IP(msg[off : off+4])
}

func TestParseQuestion(t *testing.T) {
	msg := query("Guest.Example.COM", TypeA)

	q, err := ParseQuestion(msg)
	if err != nil {
		t.Fatal(err)
	}
	off := scanQuestion(t, msg)
	if q.Name != "Guest.Example.COM" {
		t.Errorf("name = %q", q.Name)
	}
	if q.Type != TypeA || q.Class != 1 {
		t.Errorf("question = %+v, want A/IN", q)
	}
	if off != len(msg) {
		t.Errorf("answer offset = %d, want the end of the message (%d)", off, len(msg))
	}
}

func TestParseRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  []byte
	}{
		{"too short", []byte{0, 1, 2}},
		{"no question", []byte{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"name runs off the end", []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x'}},
		{"question tail cut short", []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'f', 'o', 'o', 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseQuestion(tc.msg); err == nil {
				t.Fatal("message accepted")
			}
		})
	}
}

func TestBuildAnswer(t *testing.T) {
	msg := query("host.local", TypeA)

	resp := BuildAnswer(msg, net.ParseIP("10.0.2.2"))
	if resp == nil {
		t.Fatal("no response")
	}
	h, err := ParseHeader(resp)
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != 0x1234 {
		t.Errorf("id = %04x, want the query's", h.ID)
	}
	if h.Flags&0x8000 == 0 {
		t.Errorf("flags %#04x: the response bit is not set", h.Flags)
	}
	if h.Flags&0xF != 0 {
		t.Errorf("rcode = %d, want 0", h.Flags&0xF)
	}
	if h.QDCount != 1 || h.ANCount != 1 {
		t.Errorf("counts = qd %d an %d, want 1 1", h.QDCount, h.ANCount)
	}
	if got := firstAnswer(t, resp); !got.Equal(net.ParseIP("10.0.2.2")) {
		t.Errorf("answer = %s, want 10.0.2.2", got)
	}
	// The question record itself has to survive untouched: the header changes
	// by design, and anything else would break the reply. The question is
	// written back by the same code that read it, so this is the check that the
	// round trip is byte for byte.
	end := scanQuestion(t, msg)
	if !bytes.Equal(resp[12:end], msg[12:end]) {
		t.Error("the question was rewritten")
	}
}

func TestBuildNoAnswerAndNXDomain(t *testing.T) {
	msg := query("host.local", 28) // AAAA

	noAnswer := noAnswerTo(msg)
	h, err := ParseHeader(noAnswer)
	if err != nil {
		t.Fatal(err)
	}
	if h.ANCount != 0 || h.Flags&0xF != 0 {
		t.Errorf("no answer response = %+v, want rcode 0 and no records", h)
	}

	nx := BuildNXDomain(msg)
	h, err = ParseHeader(nx)
	if err != nil {
		t.Fatal(err)
	}
	if h.ANCount != 0 || h.Flags&0xF != 3 {
		t.Errorf("nxdomain response = %+v, want rcode 3", h)
	}
}

func TestServeQuerySyntheticHost(t *testing.T) {
	s := New(nil, nil)
	s.AddHost("Host.Local.", net.ParseIP("10.0.2.2"))

	if s.HostCount() != 1 {
		t.Fatalf("host count = %d", s.HostCount())
	}

	resp, err := s.ServeQuery(query("host.local", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := firstAnswer(t, resp); !got.Equal(net.ParseIP("10.0.2.2")) {
		t.Fatalf("answer = %s, want the gateway", got)
	}

	// A known name asked for in a type we do not serve must not become
	// NXDOMAIN, or the guest's resolver gives up on the name.
	resp, err = s.ServeQuery(query("HOST.LOCAL", 28))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := ParseHeader(resp)
	if h.Flags&0xF != 0 || h.ANCount != 0 {
		t.Errorf("aaaa response = %+v, want noerror with no answers", h)
	}

	// With no upstream configured anything else is simply unknown.
	resp, err = s.ServeQuery(query("elsewhere.example", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	h, _ = ParseHeader(resp)
	if h.Flags&0xF != 3 {
		t.Errorf("unknown name rcode = %d, want nxdomain", h.Flags&0xF)
	}
}

// fakeResolver answers queries on loopback with a fixed address, so the
// upstream path can be exercised without touching the network.
type fakeResolver struct {
	conn net.PacketConn
	addr string
}

func newFakeResolver(t *testing.T, answer net.IP) *fakeResolver {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeResolver{conn: conn, addr: conn.LocalAddr().String()}
	t.Cleanup(func() { conn.Close() })

	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg := append([]byte(nil), buf[:n]...)
			resp := BuildAnswer(msg, answer)
			_, _ = conn.WriteTo(resp, peer)
		}
	}()
	return f
}

func TestUDPUpstream(t *testing.T) {
	f := newFakeResolver(t, net.ParseIP("9.9.9.9"))

	up := &udpResolver{Server: f.addr}
	resp, err := up.Exchange(query("any.example", TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if got := firstAnswer(t, resp); !got.Equal(net.ParseIP("9.9.9.9")) {
		t.Errorf("upstream answer = %s, want 9.9.9.9", got)
	}
}

func TestFailoverPicksWorkingResolver(t *testing.T) {
	f := newFakeResolver(t, net.ParseIP("9.9.9.9"))

	// A port with nothing behind it: the kernel answers with an ICMP error, so
	// the first entry fails and the second one has to be used.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	up := &Failover{Servers: []string{deadAddr, f.addr}}

	done := make(chan error, 1)
	go func() {
		resp, err := up.Exchange(query("any.example", TypeA))
		if err != nil {
			done <- err
			return
		}
		if got := firstAnswer(t, resp); !got.Equal(net.ParseIP("9.9.9.9")) {
			done <- fmt.Errorf("upstream answered %s, want 9.9.9.9", got)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("failover did not reach the working resolver")
	}

	if up.idx != 1 {
		t.Errorf("failover index = %d, want the working resolver (1)", up.idx)
	}
}

func TestParseResolvers(t *testing.T) {
	got, err := ParseResolvers("1.1.1.1, 8.8.8.8:5353 ,,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.1.1.1:53", "8.8.8.8:5353"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("resolver %d = %s, want %s", i, got[i], want[i])
		}
	}

	if _, err := ParseResolvers("resolver.no-such-host.invalid"); err == nil {
		t.Error("a resolver named by hostname was accepted")
	}
	if _, err := ParseResolvers("1.1.1.1:not-a-port"); err == nil {
		t.Error("a non numeric port was accepted")
	}
}

func TestSystemResolversAreUsable(t *testing.T) {
	list := SystemResolvers()
	if len(list) == 0 {
		t.Fatal("no resolvers at all")
	}
	for _, entry := range list {
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			t.Errorf("%q is not host:port", entry)
			continue
		}
		if net.ParseIP(host) == nil {
			t.Errorf("%q is not an IPv4 resolver", entry)
		}
		if port != "53" {
			t.Errorf("%q carries an unexpected port", entry)
		}
	}
}

// A resolver that takes the query and says nothing must not be able to hold the
// gateway: there is one query loop per DNS address, so a stuck upstream means no
// DNS at all for the guest, and Failover never reaches the resolver behind it.
func TestUDPUpstreamGivesUpOnASilentResolver(t *testing.T) {
	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()

	up := &udpResolver{Server: quiet.LocalAddr().String(), Timeout: 150 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		_, err := up.Exchange(query("any.example", TypeA))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent resolver answered")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the silent resolver is still being waited for")
	}
}

func TestFailoverSkipsASilentResolver(t *testing.T) {
	quiet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer quiet.Close()

	live := newFakeResolver(t, net.ParseIP("9.9.9.9"))
	up := &Failover{
		Servers: []string{quiet.LocalAddr().String(), live.addr},
		Timeout: 200 * time.Millisecond,
	}

	done := make(chan error, 1)
	go func() {
		resp, err := up.Exchange(query("any.example", TypeA))
		if err != nil {
			done <- err
			return
		}
		if got := firstAnswer(t, resp); !got.Equal(net.ParseIP("9.9.9.9")) {
			done <- fmt.Errorf("answered %s, want 9.9.9.9", got)
			return
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failover never reached the working resolver")
	}
}
