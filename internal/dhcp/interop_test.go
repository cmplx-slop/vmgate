package dhcp

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// A second opinion on the bytes this server puts on the wire and reads from it.
//
// The codec in this package is ours: bootp.go and options.go decode and encode
// the message by hand. A test that encodes with our Marshal and decodes with our
// Parse agrees with itself whatever the bytes are, which is exactly why the magic
// cookie stayed transposed until a QEMU guest threw the offers away. So this file
// talks to the server through github.com/insomniacslk/dhcp/dhcpv4, an
// implementation of the same RFCs written by other people: their client's
// DISCOVER has to be readable by us, and every reply we send has to be readable
// by their parser, with the same addresses and lease times in it.
//
// The dependency is a test dependency only: nothing in the gateway links against
// it, and `go list -deps ./cmd/vmgate` shows that. It is BSD-3 licensed and it
// brings three modules of its own (u-root/uio, josharian/native, pierrec/lz4).

const (
	interopXID = 0xdeadbeef
	interopMTU = 1420
)

func interopHardware() net.HardwareAddr {
	return net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
}

func interopServer() *Server {
	return NewServer(ServerConfig{
		Gateway:   net.ParseIP("10.0.2.2"),
		DNS:       []net.IP{net.ParseIP("10.0.2.2"), net.ParseIP("1.1.1.1")},
		Mask:      net.CIDRMask(24, 32),
		Pool:      Pool{Start: net.ParseIP("10.0.2.15"), Size: 8},
		LeaseTime: time.Hour,
		Domain:    "vmgate",
		MTU:       interopMTU,
	})
}

// TestParseReadsWhatAnotherImplementationSends feeds the server a request built
// by dhcpv4 and asks whether our parser reads it as its author meant.
func TestParseReadsWhatAnotherImplementationSends(t *testing.T) {
	hw := interopHardware()
	discover, err := dhcpv4.NewDiscovery(hw,
		dhcpv4.WithTransactionID(dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef}))
	if err != nil {
		t.Fatalf("dhcpv4 could not build a DISCOVER: %v", err)
	}
	wire := discover.ToBytes()

	m, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse refuses a DISCOVER dhcpv4 wrote: %v\nbytes: % x", err, wire)
	}
	if m.Type() != Discover {
		t.Errorf("the message is type %d, want DISCOVER", m.Type())
	}
	if m.XID != interopXID {
		t.Errorf("transaction id is %#08x, want %#08x", m.XID, interopXID)
	}
	if !bytes.Equal(m.CHAddr, hw) {
		t.Errorf("client hardware address is %s, want %s", m.CHAddr, hw)
	}
	if _, ok := m.Options.Get(OptMessageType); !ok {
		t.Error("the option carrying the message type did not survive our parser")
	}
}

// TestAnotherImplementationReadsOurHandshake runs the exchange with a client made
// of other people's code: their DISCOVER, our OFFER read back by their parser,
// their REQUEST built out of that OFFER the way a client builds one, and our ACK
// read back again. A lease the two implementations agree about is a lease some
// real client will take.
func TestAnotherImplementationReadsOurHandshake(t *testing.T) {
	hw := interopHardware()
	srv := interopServer()

	discover, err := dhcpv4.NewDiscovery(hw,
		dhcpv4.WithTransactionID(dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef}),
		// A client with no IP address yet can only hear a reply that is
		// broadcast, and it says so with this bit. The server has to hand it back.
		func(d *dhcpv4.DHCPv4) { d.SetBroadcast() })
	if err != nil {
		t.Fatalf("dhcpv4 could not build a DISCOVER: %v", err)
	}
	request, err := Parse(discover.ToBytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	offer, ok := srv.Handle(request)
	if !ok {
		t.Fatal("the server did not answer a DISCOVER built by dhcpv4")
	}
	offerBytes := offer.Marshal()
	if len(offerBytes) < 300 {
		t.Errorf("the offer is %d bytes; some clients drop anything shorter, which is why we pad", len(offerBytes))
	}

	got := decode(t, offerBytes)
	served := srv.Leases()
	if len(served) != 1 {
		t.Fatalf("the server holds %d leases, want one", len(served))
	}
	lease := served[0]

	checkEnvelope(t, got, hw, discover.TransactionID)
	if got.MessageType() != dhcpv4.MessageTypeOffer {
		t.Errorf("the reply is a %v, want an OFFER", got.MessageType())
	}
	if !got.YourIPAddr.Equal(lease.IP) {
		t.Errorf("the offer hands out %s, the lease table says %s", got.YourIPAddr, lease.IP)
	}
	if !got.IsBroadcast() {
		t.Error("the reply dropped the broadcast bit the client asked with")
	}
	checkOptions(t, got, lease.IP)

	// The request is now the client's job, done their way: dhcpv4 builds it out
	// of the offer, taking the address it was offered and the server it came from.
	asked, err := dhcpv4.NewRequestFromOffer(got)
	if err != nil {
		t.Fatalf("dhcpv4 could not build a REQUEST from our OFFER: %v", err)
	}
	ask, err := Parse(asked.ToBytes())
	if err != nil {
		t.Fatalf("Parse refuses the REQUEST dhcpv4 built from our OFFER: %v", err)
	}
	if ask.Type() != Request {
		t.Errorf("that message is type %d, want REQUEST", ask.Type())
	}
	if ip := ask.Options.IP(OptRequestedIP); !ip.Equal(lease.IP) {
		t.Errorf("the client asks for %s, the address we offered was %s", ip, lease.IP)
	}
	ack, ok := srv.Handle(ask)
	if !ok {
		t.Fatal("the server did not answer its own offer")
	}
	gotAck := decode(t, ack.Marshal())
	if gotAck.MessageType() != dhcpv4.MessageTypeAck {
		t.Errorf("the second reply is a %v, want an ACK", gotAck.MessageType())
	}
	if !gotAck.YourIPAddr.Equal(lease.IP) {
		t.Errorf("the ACK hands out %s, the lease table says %s", gotAck.YourIPAddr, lease.IP)
	}
	checkOptions(t, gotAck, lease.IP)
}

// decode is the reply as an independent parser sees it.
func decode(t *testing.T, msg []byte) *dhcpv4.DHCPv4 {
	t.Helper()
	got, err := dhcpv4.FromBytes(msg)
	if err != nil {
		t.Fatalf("dhcpv4 rejects what we sent: %v\nbytes: % x", err, msg)
	}
	return got
}

// checkEnvelope asserts the BOOTP fields a client uses to match a reply to the
// request it sent.
func checkEnvelope(t *testing.T, got *dhcpv4.DHCPv4, hw net.HardwareAddr, xid dhcpv4.TransactionID) {
	t.Helper()
	if got.OpCode != dhcpv4.OpcodeBootReply {
		t.Errorf("op is %v, want a BOOTP reply", got.OpCode)
	}
	if got.TransactionID != xid {
		t.Errorf("transaction id is %v, want the client's %v", got.TransactionID, xid)
	}
	if !bytes.Equal(got.ClientHWAddr, hw) {
		t.Errorf("client hardware address is %s, want %s", got.ClientHWAddr, hw)
	}
	if got.HWType.String() != "Ethernet" {
		t.Errorf("the hardware type is %v, want Ethernet", got.HWType)
	}
	if got.HopCount != 0 {
		t.Errorf("hop count is %d, want 0", got.HopCount)
	}
}

// checkOptions asserts the configuration a guest receives, read out of the reply
// by the other implementation. These are the values that decide whether the guest
// can reach anything: its address, its mask, where its default route and resolver
// are, and how long it may hold the address.
func checkOptions(t *testing.T, got *dhcpv4.DHCPv4, ip net.IP) {
	t.Helper()

	if !got.ServerIdentifier().Equal(net.ParseIP("10.0.2.2")) {
		t.Errorf("the server identifier is %s, want the gateway", got.ServerIdentifier())
	}
	if !bytes.Equal(got.SubnetMask(), net.CIDRMask(24, 32)) {
		t.Errorf("the subnet mask is %s, want /24", got.SubnetMask())
	}
	routers := got.Router()
	if len(routers) != 1 || !routers[0].Equal(net.ParseIP("10.0.2.2")) {
		t.Errorf("the routers are %v, want the gateway alone", routers)
	}
	dns := got.DNS()
	if len(dns) != 2 || !dns[0].Equal(net.ParseIP("10.0.2.2")) || !dns[1].Equal(net.ParseIP("1.1.1.1")) {
		t.Errorf("the resolvers are %v, want the gateway and 1.1.1.1", dns)
	}
	if name := got.DomainName(); name != "vmgate" {
		t.Errorf("the domain name is %q, want vmgate", name)
	}
	if !got.RequestedIPAddress().Equal(ip) {
		t.Errorf("the requested-address option says %s, want %s", got.RequestedIPAddress(), ip)
	}

	// The three lifetimes, as raw bytes: a client that reads them as big-endian
	// seconds has to get the numbers the server was configured with, and a
	// renewal that lands after the lease expires is a client that stops renewing.
	for _, tc := range []struct {
		code dhcpv4.OptionCode
		name string
		want uint32
	}{
		{dhcpv4.OptionIPAddressLeaseTime, "lease", 3600},
		{dhcpv4.OptionRenewTimeValue, "renewal", 1800},
		{dhcpv4.OptionRebindingTimeValue, "rebinding", 3150},
	} {
		val := got.Options.Get(tc.code)
		if len(val) != 4 {
			t.Errorf("the %s option is %d bytes, want 4", tc.name, len(val))
			continue
		}
		var n uint32
		for _, b := range val {
			n = n<<8 | uint32(b)
		}
		if n != tc.want {
			t.Errorf("the %s time is %d seconds, want %d", tc.name, n, tc.want)
		}
	}

	if val := got.Options.Get(dhcpv4.OptionInterfaceMTU); len(val) != 2 || uint16(val[0])<<8|uint16(val[1]) != interopMTU {
		t.Errorf("the interface MTU option is %v, want %d", val, interopMTU)
	}
}

// Where the two implementations differ about what a broken message is, the
// difference is ours to decide and write down. dhcpv4 stops at the first thing it
// cannot parse; this package keeps the options that did parse, because a reply
// that loses one option is still worth more to a guest than no reply at all, and
// because the request it is answering came from a device model that may be
// careless.
func TestBrokenRequestsWhereTheTwoDiffer(t *testing.T) {
	full := interopOffer(t)

	cases := []struct {
		name string
		give []byte

		// ours is true when our parser accepts the message; theirs when dhcpv4
		// does. The pair is recorded so a change in either is a decision, not a
		// surprise.
		ours   bool
		theirs bool
	}{
		{
			// Chopped in the middle of an option: the fields before it are
			// readable, the option itself is not.
			name: "cut inside an option",
			give: full[:270],
			ours: true,
			// Their parser reports the option it was in the middle of.
			theirs: false,
		},
		{
			// The magic cookie, transposed. This is the bug the rest of this
			// file exists to catch: it survived every test that used our own
			// encoder and decoder, and both implementations refuse it.
			name:   "a transposed magic cookie",
			give:   transposedCookie(full),
			ours:   false,
			theirs: false,
		},
	}
	for _, tc := range cases {
		_, ourErr := Parse(tc.give)
		if (ourErr == nil) != tc.ours {
			t.Errorf("%s: our parser's answer is %v, this test records acceptance=%v", tc.name, ourErr, tc.ours)
		}
		_, theirErr := dhcpv4.FromBytes(tc.give)
		if (theirErr == nil) != tc.theirs {
			t.Errorf("%s: dhcpv4's answer is %v, this test records acceptance=%v", tc.name, theirErr, tc.theirs)
		}
	}
}

// interopOffer is an OFFER from this server for a DISCOVER from the interop
// client, as bytes.
func interopOffer(t *testing.T) []byte {
	t.Helper()
	discover, err := dhcpv4.NewDiscovery(interopHardware(),
		dhcpv4.WithTransactionID(dhcpv4.TransactionID{0xde, 0xad, 0xbe, 0xef}))
	if err != nil {
		t.Fatalf("dhcpv4 could not build a DISCOVER: %v", err)
	}
	req, err := Parse(discover.ToBytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	offer, ok := interopServer().Handle(req)
	if !ok {
		t.Fatal("the server did not answer a DISCOVER")
	}
	return offer.Marshal()
}

// transposedCookie is a message with the magic cookie written the way it was
// written for months: 99.130.54.99 instead of 99.130.83.99, in the four bytes
// that follow the 236 fixed BOOTP fields.
func transposedCookie(msg []byte) []byte {
	out := append([]byte(nil), msg...)
	out[236], out[237], out[238], out[239] = 99, 130, 54, 99
	return out
}
