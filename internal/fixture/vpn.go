package fixture

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/cmplx-slop/vmgate/internal/testutil"
	"github.com/cmplx-slop/vmgate/internal/vpn"
	"github.com/cmplx-slop/vmgate/internal/wgconf"
)

// The fixture's tunnel lives far from the guest's 10.0.2.0/24 so that nothing in
// a test can confuse the two links.
const (
	tunNearIP = "10.76.0.1"
	tunFarIP  = "10.76.0.2"

	// tunMTU is smaller than the guest link's, which is what makes the gateway
	// lower the link MTU to match: a test can then check what the gateway hands
	// out, and that a frame of the tunnel's size still arrives whole.
	tunMTU = 1420
)

// farNIC is the interface number of the far side's tunnel.
const farNIC = tcpip.NICID(1)

// VPN is the fixture's side of a tunnel pair: a vpn.conf the gateway reads, and
// a second WireGuard interface with a netstack behind it standing for the
// network beyond the VPN. Both ends are wireguard-go in this process, talking
// over loopback UDP, so the tests exercise the real handshake and the real
// routes with nothing installed and no privileges.
type VPN struct {
	t   *testing.T
	stk *stack.Stack
	tun *vpn.Tunnel

	// ConfPath is the gateway's vpn.conf: put it in the configuration's
	// [vpn] conf.
	ConfPath string

	// TunnelIP is the address the gateway's own tunnel presents; FarIP is the
	// far side's, which is where a test puts the addresses beyond the VPN.
	TunnelIP net.IP
	FarIP    net.IP

	// MTU is the tunnel's MTU, and so what the gateway should hand the guest.
	MTU int
}

// NewVPN writes a matching pair of wg-quick configurations and starts the far
// end. allowed is the gateway's peer AllowedIPs, so a test can ask for a tunnel
// that carries only some destinations; nil means everything.
func NewVPN(t *testing.T, allowed []string) *VPN {
	t.Helper()

	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0"}
	}

	gPriv, gPub := keyPair(t)
	pPriv, pPub := keyPair(t)
	gPort, pPort := int(testutil.FreePort(t, "udp")), int(testutil.FreePort(t, "udp"))

	gw := tunnelSpec{
		PrivKey:   gPriv,
		IP:        tunNearIP,
		Listen:    gPort,
		MTU:       tunMTU,
		DNS:       []string{tunFarIP},
		PeerKey:   pPub,
		Endpoint:  net.JoinHostPort("127.0.0.1", strconv.Itoa(pPort)),
		Allowed:   allowed,
		Keepalive: 25,
	}
	// The far side routes only the gateway's own address back: that is what a
	// VPN server's configuration looks like, and it is enough for replies.
	peer := tunnelSpec{
		PrivKey: pPriv,
		IP:      tunFarIP,
		Listen:  pPort,
		MTU:     tunMTU,
		PeerKey: gPub,
		Allowed: []string{tunNearIP + "/32"},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.conf")
	if err := os.WriteFile(path, []byte(gw.text()), 0o600); err != nil {
		t.Fatalf("vpn conf: %v", err)
	}
	peerPath := filepath.Join(dir, "peer.conf")
	if err := os.WriteFile(peerPath, []byte(peer.text()), 0o600); err != nil {
		t.Fatalf("peer conf: %v", err)
	}

	conf, err := wgconf.Load(peerPath)
	if err != nil {
		t.Fatalf("peer conf: %v", err)
	}

	v := &VPN{
		t:        t,
		ConfPath: path,
		TunnelIP: net.ParseIP(tunNearIP),
		FarIP:    net.ParseIP(tunFarIP),
		MTU:      tunMTU,
	}
	v.start(conf)

	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("far stack: %s", stackCounters(v.stk))
		}
		_ = v.tun.Close()
		v.stk.Close()
	})
	return v
}

// start builds the far netstack around the tunnel interface: the tunnel's own
// address, and a default route back through the tunnel, which is all a network
// beyond a VPN needs.
func (v *VPN) start(conf *wgconf.Config) {
	v.stk = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	tun, err := vpn.New(conf, Logger(v.t, -1))
	if err != nil {
		v.t.Fatalf("far tunnel: %v", err)
	}
	if err := tun.Attach(v.stk, farNIC); err != nil {
		v.t.Fatalf("far tunnel attach: %v", err)
	}
	v.tun = tun

	// The far side stands for a network, not a host: it carries the addresses a
	// test gives it with AddAddress, and a network answers for the addresses it
	// carries. Promiscuous mode and address spoofing are what let the netstack
	// accept and answer a ping for an address that is not one of its own, which
	// is how a test gets a far side that replies to a relayed ping.
	if terr := v.stk.SetPromiscuousMode(farNIC, true); terr != nil {
		v.t.Fatalf("far promiscuous: %v", terr)
	}
	if terr := v.stk.SetSpoofing(farNIC, true); terr != nil {
		v.t.Fatalf("far spoofing: %v", terr)
	}

	v.stk.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		NIC:         farNIC,
	}})
}

// Stack exposes the far stack for a test that wants to build its own listeners.
func (v *VPN) Stack() *stack.Stack { return v.stk }

// AddAddress makes the far side answer for ip, as if the network beyond the VPN
// owned it. The gateway's relays dial the address the guest asked for, so a test
// that wants a guest to reach an address has to give it to the far side first.
// Naming an address the tunnel already owns is not a mistake worth failing on.
//
// It goes through the tunnel rather than the stack directly, because the far
// side is a network rather than a host: it has to carry traffic for addresses
// that are not its own, which is exactly what the tunnel's shim needs to be
// told about. The gateway itself never does this.
func (v *VPN) AddAddress(ip string) {
	v.t.Helper()

	addr := net.ParseIP(ip)
	if addr == nil {
		v.t.Fatalf("far address: %q is not an address", ip)
	}
	if err := v.tun.AddAddress(addr); err != nil {
		v.t.Fatalf("far address %s: %v", ip, err)
	}
}

// Handshake waits until the far side has answered the gateway, which is the
// point at which the tunnel can carry anything at all.
func (v *VPN) Handshake(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !v.tun.Peer().Handshake.IsZero() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
