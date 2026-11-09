package engine

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/dhcp"
	"github.com/cmplx-slop/vmgate/internal/dns"
	"github.com/cmplx-slop/vmgate/internal/ethlink"
	"github.com/cmplx-slop/vmgate/internal/nsnet"
	"github.com/cmplx-slop/vmgate/internal/svc"
	"github.com/cmplx-slop/vmgate/internal/vpn"
	"github.com/cmplx-slop/vmgate/internal/wgconf"
)

// Package engine assembles the gateway: one gVisor netstack with two
// interfaces, the link that faces QEMU and the WireGuard tunnel that carries
// everything the guest reaches beyond this machine, with the DHCP server, the
// DNS server, guest facing services and host facing forwards attached to it.
//
// The engine owns no sockets of its own beyond what the configuration asks for.
// Where a guest wants to go is dialled from inside the stack, out of the tunnel;
// the host sockets in play are the tunnel's one UDP socket and the endpoints the
// operator named in [[forward]] and [[service]]. That is what keeps the whole
// thing rootless: no raw socket, no TUN device, and no change to the host's own
// routes.

// The gateway has two interfaces: the link that faces QEMU, and the VPN tunnel
// that carries everything the guest reaches beyond this machine.
const (
	nicID  = tcpip.NICID(1)
	vpnNIC = tcpip.NICID(2)
)

// Engine is a running gateway.
type Engine struct {
	cfg config.Config
	log *slog.Logger

	stk  *stack.Stack
	link *ethlink.Endpoint

	svcm    *svc.Manager
	dnsSrv  *dns.Server
	forward *svc.Forwarder
	dhcpSrv *dhcp.Server
	tunnel  *vpn.Tunnel

	dhcpEP *nsnet.UDP

	mu         sync.Mutex
	dhcpCancel context.CancelFunc
	serving    int

	closed atomic.Bool
}

// Stats summarises what the gateway has done so far.
type Stats struct {
	Link   ethlink.Stats
	Relays int
	Conns  int

	// Paths is the datagram paths open across the gateway, which is what a
	// UDP relay costs the host beyond the listener it already has.
	Paths  int
	Denied int
	Leases []dhcp.Lease

	// EchoAnswered and EchoRelayed split the pings the gateway handled: its own
	// addresses are answered here, what the tunnel carries is relayed, and a
	// refused ping lands in neither.
	EchoAnswered int
	EchoRelayed  int

	// VPN is the tunnel's state: whether the peer is answering at all, and how
	// much has gone through.
	VPN vpn.PeerState

	// HostBridges counts the host-facing [[forward]] connections being carried
	// right now; HostRefused counts the ones turned away because the forwarder
	// already had as many as it will take.
	HostBridges int
	HostRefused int
}

// New builds a gateway: the netstack that faces QEMU, the WireGuard tunnel
// that carries everything a guest reaches beyond this machine, and the
// services a guest can see. The steps run in an order that matters: the
// tunnel's configuration decides the MTU before the link is built, the stack
// exists before anything is bound to it, and the tunnel is attached before its
// routes can decide where a guest's destinations go.
//
// Whatever fails after the stack exists is undone with Close, so a gateway
// that never started leaves no socket, no interface and no goroutine behind.
// The four steps it calls are in startup.go.
func New(cfg config.Config, log *slog.Logger, opts ...Option) (eng *Engine, err error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.dialer == nil {
		o.dialer = svc.NetDialer{}
	}
	if log == nil {
		log = slog.Default()
	}

	// The tunnel decides the largest packet the gateway can carry, and it is
	// the only way out for a guest, so its configuration is read before
	// anything else is built.
	if cfg.VPN == "" {
		return nil, errors.New("no tunnel configured: the gateway routes a guest's traffic through a VPN, so a vpn.conf has to be named ([vpn] conf)")
	}
	conf, err := wgconf.Load(cfg.VPN)
	if err != nil {
		return nil, err
	}

	e := &Engine{cfg: cfg, log: log}
	e.lowerMTU(conf)

	defer func() {
		if err != nil {
			_ = e.Close()
		}
	}()

	dnsIPs, err := e.buildStack()
	if err != nil {
		return nil, err
	}
	if err := e.buildTunnel(conf); err != nil {
		return nil, err
	}
	e.buildManager(conf, o)

	if err := e.startServices(dnsIPs); err != nil {
		return nil, err
	}
	if err := e.startDHCP(); err != nil {
		return nil, err
	}
	if err := e.startForwards(); err != nil {
		return nil, err
	}
	return e, nil
}

// MTU is the largest packet the gateway will carry, which is the smaller of the
// configured link MTU and the tunnel's. A guest learns it from DHCP and from the
// link, so this is the number it actually uses.
func (e *Engine) MTU() int { return int(e.cfg.MTU) }

// Close tears the stack down. It is safe on an engine that never finished
// starting, because New uses it to undo a failed start.
func (e *Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	e.mu.Lock()
	if e.dhcpCancel != nil {
		e.dhcpCancel()
	}
	e.mu.Unlock()

	if e.dhcpEP != nil {
		_ = e.dhcpEP.Close()
	}
	if e.forward != nil {
		e.forward.Stop()
	}
	if e.tunnel != nil {
		// Stopping the tunnel before the stack means no decrypted packet
		// arrives on an interface the stack is in the middle of taking away.
		_ = e.tunnel.Close()
	}
	if e.svcm != nil {
		e.svcm.Stop()
	}
	if e.link != nil {
		e.link.Close()
	}
	if e.stk != nil {
		e.stk.Close()
	}
	return nil
}
