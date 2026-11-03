package ethlink

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"vmgate/internal/qemu"
)

// Package ethlink connects a gVisor netstack to a stream of ethernet frames,
// such as the one QEMU's -netdev stream backend produces.
//
// The Endpoint here is a headerless link endpoint: gVisor wraps it in
// pkg/tcpip/link/ethernet, which builds and parses the ethernet header and
// drives ARP resolution. Inbound frames are pulled from a qemu.Conn by Run,
// so the transport (a QEMU socket) can be swapped whenever the guest re-plugs
// the link.

// defaultIPMTU is the payload MTU used when none was configured.
const defaultIPMTU = 1500

// Stats is a snapshot of the endpoint's traffic counters.
type Stats struct {
	RxFrames uint64
	RxBytes  uint64
	TxFrames uint64
	TxBytes  uint64

	// Dropped counts frames that went nowhere: inbound ones too damaged to
	// parse, and outbound ones the guest would not take.
	Dropped uint64

	// Held counts inbound frames the gateway took away from the stack because
	// it answered them itself, such as an ICMP echo.
	Held uint64
}

// Endpoint is the headerless link endpoint under gVisor's ethernet wrapper.
type Endpoint struct {
	mu     sync.RWMutex
	conn   qemu.Conn
	disp   stack.NetworkDispatcher
	closed bool

	// writeErr says the transport refused a frame, which ends this session: a
	// frame stream that has written part of a frame cannot write another one.
	// It is kept so that the session's log line can say why it ended, and so that
	// later writes fail at once instead of waiting on the same dead transport.
	writeErr error

	// inspect sees every inbound frame before the stack handles it and decides
	// whether the stack sees it at all: the gateway answers some frames, such as
	// an ICMP echo, by itself. The gateway also uses it to open listeners for
	// on-demand internet services.
	inspect func(fr []byte) bool

	caps stack.LinkEndpointCapabilities
	mtu  atomic.Uint32
	addr atomic.Value // tcpip.LinkAddress

	stats endpointStats
}

type endpointStats struct {
	rxFrames atomic.Uint64
	rxBytes  atomic.Uint64
	txFrames atomic.Uint64
	txBytes  atomic.Uint64
	dropped  atomic.Uint64
	held     atomic.Uint64
}

// errLinkGone is what a write finds when the endpoint has no transport to write
// to, because the gateway closed it or the guest unplugged the link.
var errLinkGone = errors.New("ethlink: link is gone")

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// New returns an endpoint carrying ipMTU sized payloads. The endpoint sits
// below the ethernet wrapper, so it reports ipMTU plus the ethernet header as
// its own MTU; the wrapper subtracts the header again for the stack.
func New(ipMTU uint32, mac net.HardwareAddr, rxChecksumOffload bool) *Endpoint {
	e := &Endpoint{caps: stack.CapabilityNone}
	if rxChecksumOffload {
		// virtio-net guests leave transport checksums to the device, and
		// QEMU strips the hint when it hands us the frame, so the stack
		// must not validate them.
		e.caps |= stack.CapabilityRXChecksumOffload
	}
	e.mtu.Store(ipMTU + header.EthernetMinimumSize)
	e.addr.Store(tcpip.LinkAddress(mac))
	return e
}

// SetInspect registers a hook that sees every inbound frame before the stack
// does and returns whether the stack may see it. A hook that answers the frame
// itself returns false, which keeps the frame from the network layer; that
// matters for ICMP, where the stack has an echo responder that cannot be
// switched off. Passing nil removes the hook.
//
// The hook runs on Run's goroutine, one frame at a time, before the frame is
// handed over: it is on the path every guest packet takes, so a hook that blocks
// stops that guest's DHCP, TCP and UDP as well. What the gateway does here is
// bookkeeping and, for one protocol, a write into the tunnel; see the note at the
// top of svc.Inspect.
func (e *Endpoint) SetInspect(fn func(fr []byte) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.inspect = fn
}

// SetConn installs the frame transport that Run consumes. The caller is
// responsible for closing any previous connection.
//
// A new transport also clears the failure of the old one: this is a different
// guest, or the same guest after a reboot, and it gets the same chance.
func (e *Endpoint) SetConn(c qemu.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conn = c
	e.writeErr = nil
}

// Stats returns a snapshot of the traffic counters.
func (e *Endpoint) Stats() Stats {
	return Stats{
		RxFrames: e.stats.rxFrames.Load(),
		RxBytes:  e.stats.rxBytes.Load(),
		TxFrames: e.stats.txFrames.Load(),
		TxBytes:  e.stats.txBytes.Load(),
		Dropped:  e.stats.dropped.Load(),
		Held:     e.stats.held.Load(),
	}
}

// MTU implements stack.LinkEndpoint.
func (e *Endpoint) MTU() uint32 {
	if mtu := e.mtu.Load(); mtu > header.EthernetMinimumSize {
		return mtu
	}
	return defaultIPMTU + header.EthernetMinimumSize
}

// SetMTU changes the payload MTU reported to the stack.
func (e *Endpoint) SetMTU(ipMTU uint32) { e.mtu.Store(ipMTU + header.EthernetMinimumSize) }

// MaxHeaderLength implements stack.LinkEndpoint. The ethernet wrapper above
// accounts for the link header, so this endpoint reserves nothing.
func (e *Endpoint) MaxHeaderLength() uint16 { return 0 }

// LinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	if v := e.addr.Load(); v != nil {
		return v.(tcpip.LinkAddress)
	}
	return ""
}

// SetLinkAddress changes the MAC address reported to the stack.
func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) { e.addr.Store(addr) }

// Capabilities implements stack.LinkEndpoint.
func (e *Endpoint) Capabilities() stack.LinkEndpointCapabilities { return e.caps }

// Attach implements stack.LinkEndpoint. The dispatcher is gVisor's ethernet
// wrapper, which parses the link header we hand it.
func (e *Endpoint) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disp = d
}

// IsAttached implements stack.LinkEndpoint.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.disp != nil
}

// Closed reports whether Close has been called.
func (e *Endpoint) Closed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.closed
}

// Wait implements stack.LinkEndpoint. Frames are read by Run, which the engine
// drives explicitly, so the stack never has to wait for us.
func (e *Endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.
func (e *Endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareEther }

// AddHeader implements stack.LinkEndpoint. The ethernet wrapper above builds
// the link header, so there is nothing to add here.
func (e *Endpoint) AddHeader(*stack.PacketBuffer) {}

// ParseHeader implements stack.LinkEndpoint. Frames arrive with their ethernet
// header intact and the wrapper consumes it.
func (e *Endpoint) ParseHeader(*stack.PacketBuffer) bool { return true }

// Close implements stack.LinkEndpoint. Closing the connection unblocks Run.
func (e *Endpoint) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	if e.conn != nil {
		e.conn.Close()
	}
}

// SetOnCloseAction implements stack.LinkEndpoint. The engine owns the
// endpoint's lifecycle, so no callback is needed.
func (e *Endpoint) SetOnCloseAction(func()) {}
