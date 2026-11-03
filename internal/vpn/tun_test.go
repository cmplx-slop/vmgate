package vpn

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// sink stands in for the stack's side of the tunnel interface: it records what
// the shim managed to inject, which is the only way to see whether a packet was
// delivered at all. An unattached endpoint silently drops whatever is injected
// into it, so the tests below attach one.
type sink struct {
	proto tcpip.NetworkProtocolNumber
	got   []byte
}

func (s *sink) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pb *stack.PacketBuffer) {
	s.proto = proto
	for _, seg := range pb.AsSlices() {
		s.got = append(s.got, seg...)
	}
}

func (s *sink) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// ours is the address a shim in these tests owns, and the only destination it
// will accept: packet() is aimed at it, so the only thing a case in
// TestShimRefusesWhatIsNotIPv4 can be about is the shape of the packet.
var ours = []tcpip.Address{tcpip.AddrFromSlice([]byte{10, 76, 0, 2})}

// packet returns bytes with a plausible IPv4 header whose declared length
// matches what is handed over, from a peer address to one of ours.
func packet(total int) []byte {
	b := make([]byte, total)
	b[0] = 0x45
	b[1] = 0
	b[2] = byte(total >> 8)
	b[3] = byte(total)
	b[8] = 64
	b[9] = 17 // UDP
	copy(b[12:16], []byte{198, 51, 100, 7})
	copy(b[16:20], []byte{10, 76, 0, 2})
	return b
}

// The peer sits on the other end of a tunnel we do not control, and it can send
// any bytes it likes once the crypto is right. Everything that is not a plain
// IPv4 packet of a sane length has to be refused before the network layer sees
// it.
func TestShimRefusesWhatIsNotIPv4(t *testing.T) {
	const mtu = 1420

	cases := []struct {
		name string
		pkt  []byte
		// aimed says the packet was well-formed and simply sent to somewhere
		// the tunnel does not carry, which is counted apart from rubbish.
		aimed bool
	}{
		{"shorter than a header", make([]byte, header.IPv4MinimumSize-1), false},
		{"not IPv4", func() []byte { p := packet(40); p[0] = 0x65; return p }(), false},
		{"header too short", func() []byte { p := packet(40); p[0] = 0x44; return p }(), false},
		{"header longer than the packet", func() []byte { p := packet(30); p[0] = 0x4f; return p }(), false},
		{"claims to be longer", func() []byte { p := packet(60); p[2] = 0; p[3] = 80; return p }(), false},
		{"claims to be shorter", func() []byte { p := packet(60); p[2] = 0; p[3] = 40; return p }(), false},
		{"larger than the interface", packet(mtu + 1), false},
		{"aimed at someone else", func() []byte { p := packet(60); copy(p[16:20], []byte{10, 0, 2, 15}); return p }(), true},
		{"aimed at the gateway's guest address", func() []byte { p := packet(60); copy(p[16:20], []byte{10, 0, 2, 2}); return p }(), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := channel.New(16, mtu, "")
			d := &sink{}
			ep.Attach(d)
			s := newShim(ep, mtu, ours)

			if _, err := s.Write([][]byte{tc.pkt}, 0); err != nil {
				t.Fatalf("write: %v", err)
			}
			// One counter or the other, never both: a peer sending rubbish and
			// a peer sending to the wrong address have to stay tellable apart.
			dropped, misaimed := s.Dropped(), s.Misaimed()
			if tc.aimed {
				if misaimed != 1 || dropped != 0 {
					t.Errorf("dropped=%d misaimed=%d, want 0 and 1", dropped, misaimed)
				}
			} else if dropped != 1 || misaimed != 0 {
				t.Errorf("dropped=%d misaimed=%d, want 1 and 0", dropped, misaimed)
			}
			if d.got != nil {
				t.Fatalf("%x reached the interface, want nothing", d.got)
			}
		})
	}
}

// A real inner packet has to arrive intact: the shim copies, because
// wireguard-go reuses its buffers, and the stack has to own what it is handed.
func TestShimCarriesIPv4(t *testing.T) {
	const mtu = 1420

	want := packet(60)

	ep := channel.New(16, mtu, "")
	d := &sink{}
	ep.Attach(d)
	s := newShim(ep, mtu, ours)

	if _, err := s.Write([][]byte{want}, 0); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := s.Dropped(); got != 0 {
		t.Fatalf("dropped = %d, want 0", got)
	}

	// wireguard-go will overwrite that buffer with the next packet it receives,
	// so the stack has to be holding a copy rather than the original.
	prefix := append([]byte(nil), want...)
	want[12] = 1

	if d.proto != header.IPv4ProtocolNumber {
		t.Errorf("delivered as protocol %d, want IPv4", d.proto)
	}
	if len(d.got) != len(prefix) {
		t.Fatalf("delivered %d bytes, want %d", len(d.got), len(prefix))
	}
	if string(d.got) != string(prefix) {
		t.Fatalf("the packet was changed on the way in: %x", d.got)
	}
}

// A packet going the other way that would not fit wireguard-go's buffer is
// dropped whole and counted separately, rather than cut down and handed over as
// though it were the packet the stack sent.
func TestShimReadDropsWhatWillNotFit(t *testing.T) {
	const mtu = 1420

	ep := channel.New(16, mtu, "")
	s := newShim(ep, mtu, ours)

	// What the stack put on the interface, in order: one packet far bigger than
	// the buffer wireguard-go offers, then one that fits.
	big := packet(2000)
	small := packet(60)
	var list stack.PacketBufferList
	list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(big),
	}))
	list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(small),
	}))
	if n, err := ep.WritePackets(list); err != nil || n != 2 {
		t.Fatalf("queued %d packets (%v), want 2", n, err)
	}

	bufs := [][]byte{make([]byte, 1024)}
	sizes := []int{0}
	n, err := s.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 1 || sizes[0] != len(small) {
		t.Fatalf("read %d bytes, want the %d byte packet", sizes[0], len(small))
	}
	if got := string(bufs[0][:sizes[0]]); got != string(small) {
		t.Fatal("the packet that came out is not the one that went in")
	}
	if got := s.Oversize(); got != 1 {
		t.Errorf("oversize = %d, want 1", got)
	}
	if got := s.Dropped(); got != 0 {
		t.Errorf("dropped = %d, want 0: that counts the peer's packets, not ours", got)
	}
}

// The MTU the shim reports is what wireguard-go sizes its buffers by, and it has
// to be the tunnel's, not the guest link's.
func TestShimReportsItsMTU(t *testing.T) {
	s := newShim(channel.New(16, 1420, ""), 1420, ours)

	if got, err := s.MTU(); err != nil || got != 1420 {
		t.Fatalf("MTU = %d (%v), want 1420", got, err)
	}
	if s.File() != nil {
		t.Error("the shim claims a file descriptor, and there is not one")
	}
	if s.BatchSize() != 1 {
		t.Errorf("BatchSize = %d, want 1", s.BatchSize())
	}
}

// Closing has to unblock the reader, which is how wireguard-go's TUN reader
// stops when the gateway shuts down.
func TestShimReadEndsOnClose(t *testing.T) {
	s := newShim(channel.New(16, 1420, ""), 1420, ours)

	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := s.Read([][]byte{make([]byte, 2048)}, []int{0}, 0); err == nil {
		t.Fatal("Read is still waiting after the tunnel closed")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
