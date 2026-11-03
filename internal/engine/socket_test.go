package engine_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/config"
	"vmgate/internal/dhcp"
	"vmgate/internal/dns"
	"vmgate/internal/engine"
	"vmgate/internal/fixture"
	"vmgate/internal/qemu"
	"vmgate/internal/testutil"
)

// TestOverQEMUSocket drives the gateway exactly the way QEMU does: a unix
// socket, the length prefixed framing "-netdev stream" uses, and raw ethernet
// frames on top of it. Nothing here is in-process, so it covers the part of the
// tool the fixture cannot: the socket, the reconnect, and Serve itself.
func TestOverQEMUSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qemu.sock")
	addr, err := qemu.ParseAddr("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	l, err := addr.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	v := fixture.NewVPN(t, nil)
	cfg := fixture.Config(t, v, func(f *config.File) {
		f.DNS.MapHosts = []string{"host.local"}
	})
	eng, err := engine.New(cfg, fixture.Logger(t, cfg.Verbose))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer eng.Close()

	// The command line accepts one connection at a time and re-serves the
	// engine after each one, which is what this does too.
	serve := make(chan error, 1)
	accept := func() net.Conn {
		t.Helper()
		go func() {
			c, err := l.Accept()
			if err != nil {
				serve <- err
				return
			}
			serve <- eng.Serve(c)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := addr.Dial(ctx)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		return conn
	}

	conn := accept()
	peer := qemu.NewStream(conn)

	// 1. The guest asks for an address.
	mac := testutil.MAC(t, "52:54:00:de:ad:01")
	xid := uint32(0xfeed)
	if err := peer.WriteFrame(bootpFrame(dhcp.Discover, mac, xid, nil)); err != nil {
		t.Fatalf("write DISCOVER: %v", err)
	}
	offer := readDHCP(t, peer)
	if offer.Type() != dhcp.Offer {
		t.Fatalf("first reply is %s, want OFFER", dhcp.TypeString(offer.Type()))
	}
	if !offer.YourIP.Equal(cfg.GuestIP) {
		t.Fatalf("OFFER yiaddr = %v, want %v", offer.YourIP, cfg.GuestIP)
	}
	if gw := offer.Options.IP(dhcp.OptServerID); !gw.Equal(cfg.GatewayIP) {
		t.Fatalf("offer server id = %v, want %v", gw, cfg.GatewayIP)
	}

	// 2. The guest, now addressed, asks the resolver for a name the gateway
	//    was told about by dns.map_hosts.
	if err := peer.WriteFrame(ipFrame(cfg.GuestIP, cfg.DNSIP, 40000, 53, dnsQuery("host.local"))); err != nil {
		t.Fatalf("write dns query: %v", err)
	}
	ip := readDNSAnswer(t, peer, mac, cfg.GuestIP)
	if !ip.Equal(cfg.GatewayIP) {
		t.Errorf("host.local resolved to %s, want the gateway %s", ip, cfg.GatewayIP)
	}

	st := eng.Stats()
	if st.Link.RxFrames < 2 || st.Link.TxFrames < 2 {
		t.Errorf("link counters = rx %d tx %d, want traffic in both directions", st.Link.RxFrames, st.Link.TxFrames)
	}

	// 3. QEMU hangs up (a guest reboot does the same). Serve has to return so
	//    the next connection can be taken.
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-serve:
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("serve ended with %v, want a clean stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after the peer went away")
	}

	// 4. Reconnect: the engine is reusable, and the lease it already handed out
	//    is still there.
	conn2 := accept()
	defer conn2.Close()
	peer2 := qemu.NewStream(conn2)
	if err := peer2.WriteFrame(bootpFrame(dhcp.Discover, mac, xid+1, nil)); err != nil {
		t.Fatalf("write second DISCOVER: %v", err)
	}
	offer = readDHCP(t, peer2)
	if offer.Type() != dhcp.Offer {
		t.Fatalf("reconnect reply is %s, want OFFER", dhcp.TypeString(offer.Type()))
	}
	if !offer.YourIP.Equal(cfg.GuestIP) {
		t.Fatalf("reconnect offered %v, want the same address %v", offer.YourIP, cfg.GuestIP)
	}
}

// bootpFrame wraps a DHCP message in the ethernet, IP and UDP headers a client
// puts on the wire before it has an address.
func bootpFrame(msgType byte, mac []byte, xid uint32, requested net.IP) []byte {
	opts := dhcp.Options{
		{Code: dhcp.OptMessageType, Value: []byte{msgType}},
	}
	if requested != nil {
		opts = append(opts, dhcp.Option{Code: dhcp.OptRequestedIP, Value: requested.To4()})
	}
	msg := dhcp.Message{
		Op:      dhcp.OpBootpRequest,
		HType:   1,
		HLen:    6,
		XID:     xid,
		Flags:   dhcp.FlagBroadcast,
		CHAddr:  mac,
		Options: opts,
	}
	return ipFrame(net.IPv4zero, net.IPv4bcast, 68, 67, msg.Marshal())
}

// readDNSAnswer reads frames until a DNS response arrives, answering the ARP
// the gateway has to do before it can reply, and returns the first A record.
func readDNSAnswer(t *testing.T, peer *qemu.Stream, ourMAC []byte, ourIP net.IP) net.IP {
	t.Helper()

	for i := 0; i < 10; i++ {
		type result struct {
			fr  []byte
			err error
		}
		ch := make(chan result, 1)
		go func() {
			fr, err := peer.ReadFrame()
			ch <- result{fr, err}
		}()

		var fr []byte
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("read frame: %v", r.err)
			}
			fr = r.fr
		case <-time.After(10 * time.Second):
			t.Fatal("no reply within 10s")
		}

		if len(fr) < header.EthernetMinimumSize {
			continue
		}
		eth := header.Ethernet(fr)
		switch eth.Type() {
		case header.ARPProtocolNumber:
			arp := header.ARP(fr[14:])
			if !arp.IsValid() || arp.Op() != header.ARPRequest {
				continue
			}
			// The gateway wants to know where ourIP is; a real guest answers
			// and the queued reply goes out straight after.
			if !bytes.Equal(arp.ProtocolAddressTarget(), ourIP.To4()) {
				continue
			}
			if err := peer.WriteFrame(arpReply(fr, ourMAC, ourIP)); err != nil {
				t.Fatalf("write arp reply: %v", err)
			}
			continue
		case header.IPv4ProtocolNumber:
		default:
			continue
		}
		ip := header.IPv4(fr[14:])
		if !ip.IsValid(len(fr)-14) || ip.Protocol() != 17 {
			continue
		}
		udp := fr[14+ip.HeaderLength():]
		if len(udp) < 12 {
			continue
		}
		payload := udp[8:]
		h, err := dns.ParseHeader(payload)
		if err != nil || h.Flags&0x8000 == 0 {
			continue
		}
		if h.ANCount == 0 {
			t.Fatalf("dns response has no answers (rcode %d)", h.Flags&0xF)
		}
		return firstA(t, payload)
	}
	t.Fatal("no dns response among the frames received")
	return nil
}

// arpReply answers an ARP request with our hardware address.
func arpReply(req []byte, ourMAC []byte, ourIP net.IP) []byte {
	sender := req[14+8 : 14+14]
	senderIP := req[14+14 : 14+18]

	fr := make([]byte, 14+28)
	copy(fr[0:], sender)
	copy(fr[6:], ourMAC)
	binary.BigEndian.PutUint16(fr[12:], 0x0806)

	a := fr[14:]
	binary.BigEndian.PutUint16(a[0:], 1)      // hardware: ethernet
	binary.BigEndian.PutUint16(a[2:], 0x0800) // protocol: ipv4
	a[4] = 6
	a[5] = 4
	binary.BigEndian.PutUint16(a[6:], 2) // operation: reply
	copy(a[8:], ourMAC)
	copy(a[14:], ourIP.To4())
	copy(a[18:], sender)
	copy(a[24:], senderIP)
	return fr
}

// firstA returns the address of the first A record in a DNS response.
func firstA(t *testing.T, msg []byte) net.IP {
	t.Helper()

	// Skip the question: name labels, then the zero length octet and four
	// bytes of type and class.
	off := 12
	for off < len(msg) && msg[off] != 0 {
		if off+int(msg[off]) >= len(msg) {
			t.Fatal("question name truncated")
		}
		off += int(msg[off]) + 1
	}
	off += 5
	if off+12 > len(msg) {
		t.Fatal("answer record truncated")
	}
	off += 2 // name pointer
	typ := binary.BigEndian.Uint16(msg[off:])
	off += 8 // type, class, ttl
	rdlen := binary.BigEndian.Uint16(msg[off:])
	off += 2
	if typ != dns.TypeA || rdlen != 4 || off+4 > len(msg) {
		t.Fatalf("first answer is type %d rdlength %d", typ, rdlen)
	}
	return net.IP(msg[off : off+4])
}
