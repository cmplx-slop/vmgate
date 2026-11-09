// Package fixture wires an engine to an in-process gVisor stack that plays the
// guest. The two stacks exchange ethernet frames over an in-memory pipe, so
// the whole gateway can be tested without QEMU, without root and without a
// single network privilege.
//
// The gateway's tunnel is paired the same way: fixture.NewVPN writes a
// wg-quick file for the gateway and builds a second wireguard-go interface with
// a netstack behind it, standing for the network beyond the VPN. That is where
// a test puts the addresses a guest wants to reach.
//
// Nothing in here is used by the gateway itself: the package exists so that a
// test can drive a whole engine, and it therefore imports testing on purpose.
package fixture

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/engine"
	"github.com/cmplx-slop/vmgate/internal/ethlink"
	"github.com/cmplx-slop/vmgate/internal/nsnet"
	"github.com/cmplx-slop/vmgate/internal/qemu"
)

// guestMAC is the MAC of the pretend guest NIC.
var guestMAC = net.HardwareAddr{0x52, 0x54, 0x11, 0x22, 0x33, 0x44}

// guestNIC is the NIC id inside the guest stack.
const guestNIC = tcpip.NICID(7)

// Net is a gateway plus a guest that can talk to it.
type Net struct {
	t   *testing.T
	Cfg config.Config
	Eng *engine.Engine

	// VPN is the tunnel pair this gateway runs against: the far side is where
	// a guest's own destinations live.
	VPN *VPN

	guest *stack.Stack
	link  *ethlink.Endpoint

	guestUp atomic.Bool
	closed  atomic.Bool
}

// New builds an engine and a guest stack joined by a frame pipe, against a
// tunnel pair whose peer carries every destination. mutate tweaks the command
// line defaults before the engine is built.
func New(t *testing.T, mutate func(*config.File), opts ...engine.Option) *Net {
	t.Helper()
	return NewAgainst(t, nil, mutate, opts...)
}

// NewAgainst is New with a tunnel whose peer carries only the AllowedIPs listed,
// which is how a test asks what happens to a destination the VPN will not route.
func NewAgainst(t *testing.T, allowed []string, mutate func(*config.File), opts ...engine.Option) *Net {
	t.Helper()

	v := NewVPN(t, allowed)
	cfg := defaultConfig(t, mutate, v.ConfPath)
	hostSide, guestSide := qemu.NewPipe()

	eng, err := engine.New(cfg, testLogger(t, cfg.Verbose), opts...)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// Wire the link up now rather than when the goroutine gets to run: tests
	// dial the host side immediately, and a forward that has no link yet fails.
	eng.Attach(hostSide)
	go func() {
		if err := eng.ServeFrame(hostSide); err != nil && cfg.Verbose >= 2 {
			t.Logf("engine link: %v", err)
		}
	}()

	n := &Net{t: t, Cfg: cfg, Eng: eng, VPN: v}
	n.guest, n.link = guestStack(t, guestSide, cfg)
	t.Cleanup(n.Close)
	return n
}

// guestStack builds the pretend guest's netstack over the far end of the pipe.
func guestStack(t *testing.T, c qemu.Conn, cfg config.Config) (*stack.Stack, *ethlink.Endpoint) {
	t.Helper()

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	ep := ethlink.New(uint32(cfg.MTU), guestMAC, false)
	ep.SetConn(c)
	if terr := s.CreateNICWithOptions(guestNIC, ethernet.New(ep), stack.NICOptions{Name: "eth0"}); terr != nil {
		t.Fatalf("guest nic: %v", nsnet.ToError(terr))
	}
	go func() {
		if err := ep.Run(); err != nil && !ep.Closed() {
			t.Logf("guest link: %v", err)
		}
	}()
	return s, ep
}

// Close tears both stacks down.
func (n *Net) Close() {
	if !n.closed.CompareAndSwap(false, true) {
		return
	}
	if n.t != nil && n.t.Failed() {
		DumpStackStats(n.t, n.Eng)
	}
	n.guest.Close()
	n.link.Close()
	n.Eng.Close()
}

// Reconnect ends the present link session and joins a fresh guest stack to the
// same engine, which is what a guest reboot or a QEMU restart looks like. The
// test then calls Configure again, as a guest that has just booted would.
func (n *Net) Reconnect() {
	n.t.Helper()

	n.guestUp.Store(false)
	n.guest.Close()

	// Closing the guest's endpoint takes the pipe down with it, which is how
	// the engine finds out the session is over.
	n.link.Close()

	// The engine notices the dead link on its own, but the session has to have
	// ended before a new one is attached: ServeFrame clears the link on the way
	// out, and clearing it after the new one was attached would drop it.
	deadline := time.Now().Add(10 * time.Second)
	for n.Eng.Serving() > 0 {
		if time.Now().After(deadline) {
			n.t.Fatal("the engine never noticed the link going away")
		}
		time.Sleep(5 * time.Millisecond)
	}

	hostSide, guestSide := qemu.NewPipe()
	n.Eng.Attach(hostSide)
	go func() {
		if err := n.Eng.ServeFrame(hostSide); err != nil && n.Cfg.Verbose >= 2 {
			n.t.Logf("engine link: %v", err)
		}
	}()

	n.guest, n.link = guestStack(n.t, guestSide, n.Cfg)
}

// Configure gives the guest its address and a default route through the
// gateway, which is what a successful DHCP run amounts to.
func (n *Net) Configure() {
	n.t.Helper()

	ones, _ := n.Cfg.Mask.Size()
	addr := tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   nsnet.AddrOf(n.Cfg.GuestIP),
			PrefixLen: ones,
		},
	}
	if terr := n.guest.AddProtocolAddress(guestNIC, addr, stack.AddressProperties{}); terr != nil {
		n.t.Fatalf("guest address: %v", nsnet.ToError(terr))
	}
	n.guest.SetRouteTable([]tcpip.Route{{
		Destination: header.IPv4EmptySubnet,
		Gateway:     nsnet.AddrOf(n.Cfg.GatewayIP),
		NIC:         guestNIC,
	}})
	n.guestUp.Store(true)
}

// Stack exposes the guest stack for low level tests.
func (n *Net) Stack() *stack.Stack { return n.guest }

// GuestMAC returns the MAC address of the pretend guest.
func (n *Net) GuestMAC() string { return guestMAC.String() }

// DialTCP opens a TCP connection from the guest to address:port.
func (n *Net) DialTCP(ctx context.Context, address string, port uint16) (net.Conn, error) {
	if !n.guestUp.Load() {
		return nil, fmt.Errorf("fixture: guest is not configured")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("fixture: %q is not an address", address)
	}
	local := nsnet.Full(guestNIC, n.Cfg.GuestIP, 0)
	remote := nsnet.Full(guestNIC, ip, port)
	conn, err := gonet.DialTCPWithBind(ctx, n.guest, local, remote, header.IPv4ProtocolNumber)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// ListenTCP makes the guest listen on its own address, so inbound forwards can
// be exercised.
func (n *Net) ListenTCP(port uint16) (*gonet.TCPListener, error) {
	if !n.guestUp.Load() {
		return nil, fmt.Errorf("fixture: guest is not configured")
	}
	return gonet.ListenTCP(n.guest, nsnet.Full(guestNIC, n.Cfg.GuestIP, port), header.IPv4ProtocolNumber)
}

// Exchange sends one datagram from the guest and returns the first reply.
func (n *Net) Exchange(msg []byte, to net.IP, port uint16, timeout time.Duration) ([]byte, error) {
	if !n.guestUp.Load() {
		return nil, fmt.Errorf("fixture: guest is not configured")
	}
	ep, err := nsnet.ListenUDP(n.guest, guestNIC, nil, 0)
	if err != nil {
		return nil, err
	}
	defer ep.Close()

	if _, err := ep.WriteTo(msg, &net.UDPAddr{IP: to, Port: int(port)}); err != nil {
		return nil, err
	}

	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _, err := ep.Read(buf)
		if err != nil {
			ch <- result{nil, err}
			return
		}
		ch <- result{append([]byte(nil), buf[:n]...), nil}
	}()
	select {
	case r := <-ch:
		return r.b, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("fixture: no reply within %v", timeout)
	}
}

// testLogger keeps test output quiet unless the verbosity flag asks for more.
// Set VMGATE_TEST_LOGS=1 to see what the gateway is doing while debugging.
func testLogger(t *testing.T, verbosity int) *slog.Logger {
	level := slog.LevelError
	w := io.Discard
	if os.Getenv("VMGATE_TEST_LOGS") != "" {
		level, w = slog.LevelDebug, os.Stderr
	} else if verbosity >= 2 {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

// Raw is an engine with the far end of the frame pipe in hand and no guest
// stack attached, for tests that want to speak raw ethernet frames.
type Raw struct {
	Cfg config.Config
	Eng *engine.Engine

	// Frames is the far end of the pipe: ethernet frames written there reach
	// the gateway, and frames the gateway sends can be read back.
	Frames *qemu.Stream

	// VPN is the tunnel pair the engine was built against.
	VPN *VPN
}

// Link builds an engine plus the far end of the frame pipe with no guest stack
// attached, for tests that want to speak raw ethernet frames.
func Link(t *testing.T, mutate func(*config.File), opts ...engine.Option) *Raw {
	t.Helper()
	return LinkAgainst(t, nil, mutate, opts...)
}

// LinkAgainst is Link with a tunnel whose peer carries only the AllowedIPs
// listed, for tests that want to see what a destination the VPN will not route
// looks like from the guest's side.
func LinkAgainst(t *testing.T, allowed []string, mutate func(*config.File), opts ...engine.Option) *Raw {
	t.Helper()

	v := NewVPN(t, allowed)
	cfg := defaultConfig(t, mutate, v.ConfPath)
	hostSide, guestSide := qemu.NewPipe()

	eng, err := engine.New(cfg, testLogger(t, cfg.Verbose), opts...)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	eng.Attach(hostSide)
	go func() {
		if err := eng.ServeFrame(hostSide); err != nil && cfg.Verbose >= 2 {
			t.Logf("engine link: %v", err)
		}
	}()
	t.Cleanup(func() {
		if t.Failed() {
			DumpStackStats(t, eng)
		}
		_ = eng.Close()
	})
	return &Raw{Cfg: cfg, Eng: eng, Frames: guestSide, VPN: v}
}

// Config returns the configuration file defaults with mutate applied, using the
// tunnel pair v. Tests that build an engine themselves, rather than through New
// or Link, still need the same starting point the tool uses.
func Config(t *testing.T, v *VPN, mutate func(*config.File)) config.Config {
	t.Helper()
	return defaultConfig(t, mutate, v.ConfPath)
}

// Logger returns the fixture's logger for engines built outside it.
func Logger(t *testing.T, verbosity int) *slog.Logger {
	t.Helper()
	return testLogger(t, verbosity)
}

// defaultConfig starts from the file defaults the tool uses, applies the
// test's tweaks to that file shape, and resolves it. The lease is shortened and
// the logging turned down because tests would rather be quick and quiet; the
// engine's own logger is picked by testLogger. vpnConf names the wg-quick file
// the guest's tunnel is built from, which the tool requires as well.
func defaultConfig(t *testing.T, mutate func(*config.File), vpnConf string) config.Config {
	t.Helper()

	f := config.DefaultFile()
	f.DHCP.LeaseTime = time.Hour.String()
	f.Log.Verbosity = -1
	f.VPN.Conf = vpnConf
	if mutate != nil {
		mutate(&f)
	}
	cfg, err := config.Resolve(f)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}
