package vpn

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"vmgate/internal/nsnet"
	"vmgate/internal/wgconf"
)

// Package vpn runs a WireGuard interface entirely inside this process: the
// tunnel's "network card" is a gVisor channel endpoint, and wireguard-go does
// the crypto on the other side of it. Nothing is created on the host but one
// UDP socket, so the whole thing works without root, without a TUN device and
// without touching the host's routing table.
//
// The tunnel is the only way a guest reaches anything beyond the gateway. That
// is deliberate, and it comes with two consequences worth knowing:
//
//   - The destinations that can be reached are exactly the peer's AllowedIPs:
//     the gateway builds one route per AllowedIPs entry, pinned to the tunnel
//     interface, and a guest connection to anything else fails as unreachable
//     rather than going out some other way.
//   - The resolvers named in the tunnel configuration are asked through the
//     tunnel, so nothing the guest looks up is answered by the host's
//     connection either.

// NICName is how the tunnel interface appears inside the stack.
const NICName = "vpn"

// queueSize is how many packets the tunnel interface may hold while wireguard-
// go catches up. Sized like the guest interface: a burst is expected, a
// permanently full queue means the peer is gone.
const queueSize = 1024

// Tunnel is one WireGuard interface, attached to one stack.
type Tunnel struct {
	conf *wgconf.Config
	log  *slog.Logger

	ep   *channel.Endpoint
	shim *tunShim
	dev  *device.Device

	// stk and nic are set by Attach and read by every egress dial.
	stk *stack.Stack
	nic tcpip.NICID

	attached atomic.Bool
	closed   atomic.Bool
}

// New reads the tunnel into being: the configuration is checked, the peer's
// endpoint is resolved, and wireguard-go is configured but not started. Nothing
// can reach the network until Attach has given the stack an interface to put
// packets on, which is why starting up and attaching are separate steps.
func New(conf *wgconf.Config, log *slog.Logger) (*Tunnel, error) {
	if conf == nil {
		return nil, errors.New("vpn: no configuration")
	}
	if log == nil {
		log = slog.Default()
	}
	// A Config from Load is already validated; saying it again here is what
	// lets the rest of this function assume one peer, an IPv4 address and a
	// usable MTU without checking each time.
	if err := conf.Validate(); err != nil {
		return nil, fmt.Errorf("vpn: %w", err)
	}

	// Reaching the peer is control traffic, before the tunnel carries anything,
	// so it is the one place the host's resolver is used.
	if err := conf.ResolveEndpoints(nil); err != nil {
		return nil, err
	}

	t := &Tunnel{
		conf: conf,
		log:  log,
		ep:   channel.New(queueSize, uint32(conf.MTU), ""),
	}
	// The shim judges what the peer may send, and "may send" includes where it
	// may send it: only the addresses this tunnel owns.
	t.shim = newShim(t.ep, conf.MTU, tunnelAddresses(conf))
	t.dev = device.NewDevice(t.shim, conn.NewDefaultBind(), wgLogger(log))

	if err := t.dev.IpcSet(conf.UAPI()); err != nil {
		t.Close()
		return nil, fmt.Errorf("vpn: wireguard refused the configuration: %v", err)
	}
	if conf.Peers[0].Endpoint == "" {
		log.Warn("vpn: peer has no Endpoint, so it must dial in; the guest cannot reach anything until it does")
	}
	return t, nil
}

// Attach puts the tunnel on the stack as nic and starts it. The order matters:
// the interface and its address must exist before the first decrypted packet
// arrives, and the device does not bind or start its peer until Up.
func (t *Tunnel) Attach(stk *stack.Stack, nic tcpip.NICID) error {
	if stk == nil {
		return errors.New("vpn: no stack to attach to")
	}
	if t.closed.Load() {
		return errors.New("vpn: tunnel is closed")
	}
	if t.attached.Swap(true) {
		return errors.New("vpn: tunnel attached twice")
	}

	terr := stk.CreateNICWithOptions(nic, t.ep, stack.NICOptions{Name: NICName})
	if terr != nil {
		return fmt.Errorf("vpn: %v", nsnet.ToError(terr))
	}
	// These are the addresses tunnelAddresses handed the shim when the tunnel
	// was built, from the same configuration: an interface that answers for an
	// address the tunnel refuses to deliver is an address that looks alive and
	// drops its own traffic, so the two lists have one source. AddAddress is
	// the only other way an address gets here, and it moves both halves.
	for _, pre := range t.conf.Addresses {
		if !pre.Addr().Is4() {
			continue
		}
		addr := tcpip.ProtocolAddress{
			Protocol: header.IPv4ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(pre.Addr().AsSlice()),
				PrefixLen: pre.Bits(),
			},
		}
		if terr := stk.AddProtocolAddress(nic, addr, stack.AddressProperties{}); terr != nil {
			stk.RemoveNIC(nic)
			return fmt.Errorf("vpn: address %s: %v", pre, nsnet.ToError(terr))
		}
	}

	t.stk = stk
	t.nic = nic

	if err := t.dev.Up(); err != nil {
		// The NIC and its addresses are ours to take back down: a stack left
		// with a half-built tunnel interface answers for an address nothing
		// can reach.
		stk.RemoveNIC(nic)
		return fmt.Errorf("vpn: the tunnel could not start: %v", err)
	}

	// The port wg bound is worth naming: it is the one thing an operator has
	// to open in a firewall when the peer dials in, and it is not known until
	// the socket exists.
	args := []any{
		"nic", NICName, "id", uint8(nic), "address", t.IP(), "mtu", t.MTU(),
		"listen_port", t.Peer().ListenPort,
		"routes", len(t.Routes()), "dns", t.DNS(),
		"peer", shortKey(t.conf.Peers[0].PublicKey), "endpoint", orNone(t.conf.Peers[0].Endpoint),
	}
	if name := t.conf.Peers[0].EndpointName; name != "" {
		// The address above came out of the host's resolver, which is the one
		// lookup here that does not go through the tunnel. Saying both halves
		// is what makes a wrong answer visible.
		args = append(args, "endpoint_name", name)
	}
	t.log.Info("vpn: tunnel up", args...)
	return nil
}

// Close stops the tunnel. It is safe to call more than once.
func (t *Tunnel) Close() error {
	if t.closed.Swap(true) {
		return nil
	}
	t.dev.Close() // closes the shim, and so the endpoint
	return nil
}

// IP is the tunnel's IPv4 address: the source address of everything the guest
// sends through the tunnel.
func (t *Tunnel) IP() net.IP { return t.conf.TunnelIP() }

// MTU is the tunnel's MTU.
func (t *Tunnel) MTU() int { return t.conf.MTU }

// DNS are the resolvers named in the tunnel configuration.
func (t *Tunnel) DNS() []net.IP { return t.conf.DNS }

// path is the attached stack and interface every dial needs.
//
// stk and nic have one writer, Attach, and it runs before this tunnel can be
// dialed: the engine builds its manager after attaching, and nothing else is
// handed the tunnel early enough to race. AddAddress reads them on the same
// assumption. If that ordering ever changes, this is where the lock belongs.
func (t *Tunnel) path() (*stack.Stack, tcpip.NICID, error) {
	if t.stk == nil {
		return nil, 0, errors.New("vpn: tunnel is not attached")
	}
	if t.closed.Load() {
		return nil, 0, errors.New("vpn: tunnel is closed")
	}
	return t.stk, t.nic, nil
}

// wgLogger routes wireguard-go's own noise into the gateway's log. Its error
// lines are worth seeing; its verbose lines are not, unless the packet log is
// on, and slog decides that by level.
func wgLogger(log *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug("wireguard: " + fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			log.Error("wireguard: " + fmt.Sprintf(format, args...))
		},
	}
}
