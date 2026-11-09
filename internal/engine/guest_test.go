package engine_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/dhcp"
	"github.com/cmplx-slop/vmgate/internal/fixture"
	"github.com/cmplx-slop/vmgate/internal/testutil"
)

// TestInboundForward is the [[forward]] case: a socket on the host
// dials into the guest, which is how ssh into a VM works without privileges.
func TestInboundForward(t *testing.T) {
	const guestPort = 9999
	hostPort := testutil.FreePort(t, "tcp")

	n := fixture.New(t, func(f *config.File) {
		f.Forward = []config.Forward{{
			HostAddr:  "127.0.0.1",
			HostPort:  hostPort,
			GuestAddr: f.Network.GuestIP,
			GuestPort: guestPort,
		}}
	})
	n.Configure()

	l, err := n.ListenTCP(guestPort)
	if err != nil {
		t.Fatalf("guest listen :%d: %v", guestPort, err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			if _, err := fmt.Fprintf(conn, "guest:%s\n", sc.Text()); err != nil {
				return
			}
		}
		// A truncated line only stops this echo: the test's own assertion is
		// what notices when an answer never arrives.
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", hostPort), 10*time.Second)
	if err != nil {
		t.Fatalf("host dial :%d: %v", hostPort, err)
	}
	defer conn.Close()

	if got, want := exchange(t, conn, "ssh"), "guest:ssh"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestDHCPFromFrames drives the DHCP server the way a firmware would: a
// broadcast DISCOVER on the wire, an OFFER back, then REQUEST and ACK.
func TestDHCPFromFrames(t *testing.T) {
	r := fixture.Link(t, nil)
	cfg, peer := r.Cfg, r.Frames

	mac := testutil.MAC(t, "52:54:00:aa:bb:cc")
	xid := uint32(0x1234)

	disc := dhcp.Message{
		Op:     dhcp.OpBootpRequest,
		HType:  1,
		HLen:   6,
		XID:    xid,
		Flags:  dhcp.FlagBroadcast,
		CHAddr: mac,
		Options: dhcp.Options{
			{Code: dhcp.OptMessageType, Value: []byte{dhcp.Discover}},
		},
	}
	if err := peer.WriteFrame(ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, disc.Marshal())); err != nil {
		t.Fatalf("write DISCOVER: %v", err)
	}

	offer := readDHCP(t, peer)
	if offer.Type() != dhcp.Offer {
		t.Fatalf("first reply is %s, want OFFER", dhcp.TypeString(offer.Type()))
	}
	if !offer.YourIP.Equal(cfg.GuestIP) {
		t.Fatalf("OFFER yiaddr = %v, want %v", offer.YourIP, cfg.GuestIP)
	}

	req := dhcp.Message{
		Op:     dhcp.OpBootpRequest,
		HType:  1,
		HLen:   6,
		XID:    xid,
		Flags:  dhcp.FlagBroadcast,
		CHAddr: mac,
		Options: dhcp.Options{
			{Code: dhcp.OptMessageType, Value: []byte{dhcp.Request}},
			{Code: dhcp.OptRequestedIP, Value: offer.YourIP.To4()},
			{Code: dhcp.OptServerID, Value: cfg.GatewayIP.To4()},
		},
	}
	if err := peer.WriteFrame(ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, req.Marshal())); err != nil {
		t.Fatalf("write REQUEST: %v", err)
	}
	ack := readDHCP(t, peer)
	if ack.Type() != dhcp.Ack {
		t.Fatalf("second reply is %s, want ACK", dhcp.TypeString(ack.Type()))
	}
	if !ack.YourIP.Equal(cfg.GuestIP) {
		t.Fatalf("ACK yiaddr = %v, want %v", ack.YourIP, cfg.GuestIP)
	}

	leases := r.Eng.Stats().Leases
	if len(leases) != 1 || !leases[0].IP.Equal(cfg.GuestIP) {
		t.Fatalf("leases = %v, want one for %v", leases, cfg.GuestIP)
	}
}

// TestDHCPForAHandAssembledRequest drives the server with a DISCOVER written
// out byte by byte, the way a client writes one, rather than with our own
// encoder. Encoding and decoding with the same code hides a wrong magic cookie
// in both directions, and a wrong cookie is a DHCP that looks silent from the
// guest: the request never gets as far as its options here, and the answer is a
// packet no client will open.
func TestDHCPForAHandAssembledRequest(t *testing.T) {
	r := fixture.Link(t, nil)
	cfg, peer := r.Cfg, r.Frames

	mac := testutil.MAC(t, "52:54:00:aa:bb:cc")
	xid := uint32(0x13579bdf)
	if err := peer.WriteFrame(ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, handAssembledDiscover(mac, xid))); err != nil {
		t.Fatalf("write DISCOVER: %v", err)
	}

	fr := readDHCPFrame(t, peer)
	body := dhcpBytesFromFrame(t, fr)
	if len(body) < 240 {
		t.Fatalf("reply is only %d bytes", len(body))
	}
	if got := body[236:240]; !bytes.Equal(got, []byte{0x63, 0x82, 0x53, 0x63}) {
		t.Fatalf("reply magic cookie = % x, want 63 82 53 63: nothing after it is readable by a client", got)
	}

	msg := dhcpFromFrame(t, fr)
	if msg.Type() != dhcp.Offer {
		t.Fatalf("reply is %s, want OFFER", dhcp.TypeString(msg.Type()))
	}
	if msg.XID != xid {
		t.Fatalf("xid = %x, want %x", msg.XID, xid)
	}
	if !msg.YourIP.Equal(cfg.GuestIP) {
		t.Fatalf("OFFER yiaddr = %v, want %v", msg.YourIP, cfg.GuestIP)
	}
	if !bytes.Equal(msg.CHAddr, mac) {
		t.Fatalf("chaddr = %v, want %v", msg.CHAddr, mac)
	}
	// The options a client needs to bring the interface up without guessing.
	for _, code := range []byte{dhcp.OptMessageType, dhcp.OptServerID, dhcp.OptSubnetMask, dhcp.OptRouter, dhcp.OptLeaseTime, dhcp.OptDNS} {
		if _, ok := msg.Options.Get(code); !ok {
			t.Errorf("OFFER has no option %d", code)
		}
	}
}

// handAssembledDiscover writes a DISCOVER as a client does: fixed fields, the
// cookie the RFC names (99.130.83.99), then options as bytes, padded past the
// 300 byte BOOTP minimum. The offsets are spelled as numbers here on purpose:
// they are the client's numbers, not ours.
func handAssembledDiscover(mac []byte, xid uint32) []byte {
	opts := []byte{53, 1, 1} // message type: DISCOVER
	opts = append(opts, 61, byte(len(mac)+1), 1)
	opts = append(opts, mac...) // client identifier, which dhclient always sends
	vendor := []byte("dhcp-4.4.3-P1")
	opts = append(opts, 60, byte(len(vendor)))
	opts = append(opts, vendor...)
	want := []byte{1, 3, 6, 15, 26, 28, 42, 51, 54, 58, 119, 121, 249, 114}
	opts = append(opts, 55, byte(len(want))) // parameter request list
	opts = append(opts, want...)
	opts = append(opts, 255) // end
	for len(opts) < 64 {
		opts = append(opts, 0) // pad, as a client does
	}

	b := make([]byte, 240+len(opts))
	b[0] = 1 // BOOTREQUEST
	b[1] = 1 // ethernet
	b[2] = byte(len(mac))
	binary.BigEndian.PutUint32(b[4:8], xid)
	binary.BigEndian.PutUint16(b[10:12], 0x8000) // the broadcast flag
	copy(b[28:28+len(mac)], mac)
	copy(b[236:240], []byte{0x63, 0x82, 0x53, 0x63}) // the RFC's magic cookie
	copy(b[240:], opts)
	return b
}
