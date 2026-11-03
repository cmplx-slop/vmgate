package nsnet

import (
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"

	"vmgate/internal/ethlink"
)

// The gateway writes exactly one kind of ICMP itself, so the byte level
// behaviour of that one socket is worth pinning without a whole gateway around
// it: what leaves is an echo request carrying the identifier the stack chose and
// the sequence number asked for, and what comes back is read out of an answer.
func TestEchoSocketSendsAndReads(t *testing.T) {
	const tunnel tcpip.NICID = 1

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
	})
	defer stk.Close()

	queue := attach(t, stk, tunnel, "10.76.0.2")
	stk.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: tunnel}})

	p, err := DialEcho(stk, tunnel, net.ParseIP("10.76.0.9"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer p.Close()
	if p.Ident() == 0 {
		t.Error("the stack gave the socket no identifier, so its answers could not be found")
	}

	if err := p.Send(4, []byte("ping")); err != nil {
		t.Fatalf("send: %v", err)
	}
	pb := queue.Read()
	if pb == nil {
		t.Fatal("the request never left the interface")
	}
	sent := join(pb)
	pb.DecRef()

	echo, ok := ethlink.ParseEcho(linked(sent))
	if !ok {
		t.Fatalf("what left the interface is not an icmp echo: %d bytes", len(sent))
	}
	if echo.Type != ethlink.TypeEcho {
		t.Errorf("type = %d, want an echo request", echo.Type)
	}
	if echo.Ident != p.Ident() {
		t.Errorf("identifier on the wire = %d, want the socket's %d", echo.Ident, p.Ident())
	}
	if echo.Seq != 4 || string(echo.Payload) != "ping" {
		t.Errorf("seq/payload = %d/%q, want 4/ping", echo.Seq, echo.Payload)
	}
	if !echo.SrcIP.Equal(net.ParseIP("10.76.0.2")) || !echo.DstIP.Equal(net.ParseIP("10.76.0.9")) {
		t.Errorf("request went %s to %s, the socket's address to the address it dialled", echo.SrcIP, echo.DstIP)
	}

	// The far side answers with the socket's identifier, which is what the
	// stack matched the reply to the socket by.
	writeIn(t, queue, ethlink.EchoFrame(ethlink.Echo{
		SrcIP:   net.ParseIP("10.76.0.9"),
		DstIP:   net.ParseIP("10.76.0.2"),
		Type:    ethlink.TypeEchoReply,
		Ident:   p.Ident(),
		Seq:     4,
		Payload: []byte("ping"),
	}))

	seq, payload := answerWithin(t, p, 2*time.Second)
	if seq != 4 || string(payload) != "ping" {
		t.Errorf("answer seq/payload = %d/%q, want 4/ping", seq, payload)
	}
}

// An answer for somebody else's identifier must not turn up on this socket: the
// stack matches it by identifier, which is what stops a host on the far side of
// the tunnel from answering a ping it was never part of.
func TestEchoSocketReadsOnlyItsOwnAnswers(t *testing.T) {
	const tunnel tcpip.NICID = 1

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
	})
	defer stk.Close()

	queue := attach(t, stk, tunnel, "10.76.0.2")
	stk.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: tunnel}})

	p, err := DialEcho(stk, tunnel, net.ParseIP("10.76.0.9"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer p.Close()

	// Somebody else's answer first, with a sequence number that would give it
	// away if it turned up here, then the one this socket asked for.
	writeIn(t, queue, ethlink.EchoFrame(ethlink.Echo{
		SrcIP:   net.ParseIP("10.76.0.9"),
		DstIP:   net.ParseIP("10.76.0.2"),
		Type:    ethlink.TypeEchoReply,
		Ident:   p.Ident() + 1,
		Seq:     99,
		Payload: []byte("wrong"),
	}))
	writeIn(t, queue, ethlink.EchoFrame(ethlink.Echo{
		SrcIP:   net.ParseIP("10.76.0.9"),
		DstIP:   net.ParseIP("10.76.0.2"),
		Type:    ethlink.TypeEchoReply,
		Ident:   p.Ident(),
		Seq:     1,
		Payload: []byte("mine"),
	}))

	seq, payload := answerWithin(t, p, 2*time.Second)
	if seq != 1 || string(payload) != "mine" {
		t.Errorf("first answer was %d/%q, want the one carrying this socket's identifier", seq, payload)
	}
}

// The same gate DialUDP has, on the socket a ping uses: an interface with no
// route for a destination cannot carry traffic for it, which is how a destination
// outside the peer's AllowedIPs is refused.
func TestDialEchoNeedsARouteOnThatInterface(t *testing.T) {
	const (
		tunnel tcpip.NICID = 1
		link   tcpip.NICID = 2
	)

	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{icmp.NewProtocol4},
	})
	defer stk.Close()

	attach(t, stk, tunnel, "10.76.0.2")
	attach(t, stk, link, "10.0.2.2")
	stk.SetRouteTable([]tcpip.Route{{
		Destination: tcpip.AddressWithPrefix{
			Address:   AddrOf(net.ParseIP("10.0.2.0")),
			PrefixLen: 24,
		}.Subnet(),
		NIC: link,
	}})

	if _, err := DialEcho(stk, tunnel, net.ParseIP("93.184.216.34")); err == nil {
		t.Fatal("a destination with no route on the pinned interface was dialled anyway")
	}
}

// answerWithin reads with a deadline, so a missing answer fails the test instead
// of hanging it.
func answerWithin(t *testing.T, p *Echo, within time.Duration) (uint16, []byte) {
	t.Helper()

	type result struct {
		seq     uint16
		payload []byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		seq, payload, err := p.Answer(make([]byte, 1024))
		done <- result{seq, payload, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("answer: %v", r.err)
		}
		return r.seq, r.payload
	case <-time.After(within):
		t.Fatalf("no answer within %v", within)
		return 0, nil
	}
}

// writeIn feeds one IPv4 packet to the interface, as if it had come down the
// tunnel. The channel endpoint stands where a link endpoint stands, so the link
// header is not part of what it hands over.
func writeIn(t *testing.T, q *channel.Endpoint, frame []byte) {
	t.Helper()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(linkless(frame)),
	})
	q.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

// linked puts an ethernet header on a packet, so the gateway's frame parser can
// read what the stack wrote.
func linked(packet []byte) []byte {
	fr := make([]byte, 0, len(packet)+14)
	fr = append(fr, make([]byte, 12)...)
	fr = append(fr, 0x08, 0x00)
	return append(fr, packet...)
}

// linkless is the same in the other direction.
func linkless(frame []byte) []byte {
	return frame[14:]
}

// join flattens a packet buffer into one slice.
func join(pb *stack.PacketBuffer) []byte {
	var out []byte
	for _, s := range pb.AsSlices() {
		out = append(out, s...)
	}
	return out
}
