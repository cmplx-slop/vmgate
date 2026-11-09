package svc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/cmplx-slop/vmgate/internal/nsnet"
)

// Forwarder is the other direction: sockets opened on the host that dial into
// the guest through the netstack, which is what a [[forward]] entry is. With
// host_port 2222 and guest_port 22, ssh on the host connects to 127.0.0.1:2222
// and lands on the guest's port 22, exactly the way QEMU's
// "-netdev user,hostfwd" works, but without any privileges.
//
// It sits next to Manager rather than inside it because it holds nothing the
// guest's frames decide: the listeners exist because the operator wrote them
// down, and no relay table or egress policy is consulted on the way.
type Forwarder struct {
	stk *stack.Stack
	nic tcpip.NICID
	log *slog.Logger

	mu        sync.Mutex
	listeners []net.Listener
	conns     []net.PacketConn
	bridges   int
	refused   int
	stopped   bool
	src       net.IP
}

// maxBridges is how many host connections one forwarder carries at a time. A
// [[forward]] is opened on the host's own address at the operator's request, so
// whoever can reach that address can ask for a guest connection: without a
// ceiling, that is a goroutine, a host socket and a netstack endpoint per
// connection, and the guest is the one that runs out of everything first.
const maxBridges = 64

// NewForwarder returns a forwarder that dials guests through stk.
func NewForwarder(stk *stack.Stack, nic tcpip.NICID, log *slog.Logger) *Forwarder {
	if log == nil {
		log = slog.Default()
	}
	return &Forwarder{stk: stk, nic: nic, log: log}
}

// Stop closes every host listener. In-flight connections finish on their own.
func (f *Forwarder) Stop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	for _, l := range f.listeners {
		_ = l.Close()
	}
	for _, c := range f.conns {
		_ = c.Close()
	}
}

// ForwardTCP listens on hostAddr on the host and connects every accepted
// connection to guestIP:guestPort inside the guest.
func (f *Forwarder) ForwardTCP(hostAddr string, guestIP net.IP, guestPort uint16) error {
	l, err := net.Listen("tcp", hostAddr)
	if err != nil {
		return err
	}
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		_ = l.Close()
		return errors.New("svc: forwarder stopped")
	}
	f.listeners = append(f.listeners, l)
	f.mu.Unlock()

	f.log.Info("forward: tcp", "host", l.Addr(), "guest", net.JoinHostPort(guestIP.String(), strconv.Itoa(int(guestPort))))
	go f.accept(l, guestIP, guestPort)
	return nil
}

func (f *Forwarder) accept(l net.Listener, guestIP net.IP, guestPort uint16) {
	for {
		host, err := l.Accept()
		if err != nil {
			f.mu.Lock()
			stopped := f.stopped
			f.mu.Unlock()
			if !stopped {
				f.log.Debug("forward: tcp accept", "err", err)
			}
			return
		}
		if !f.takeBridge() {
			// Said quietly: whoever is filling the forward gets no more from the
			// log than from the socket, and the counters say what happened.
			f.log.Debug("forward: too many host connections",
				"host", host.RemoteAddr(), "guest", guestIP, "limit", maxBridges)
			_ = host.Close()
			continue
		}
		go f.bridge(host, guestIP, guestPort)
	}
}

// takeBridge claims room for one host connection, and says when there is none.
func (f *Forwarder) takeBridge() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridges >= maxBridges {
		f.refused++
		return false
	}
	f.bridges++
	return true
}

func (f *Forwarder) dropBridge() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bridges > 0 {
		f.bridges--
	}
}

// Bridges is how many host connections the forwarder is carrying, and
// BridgesRefused how many it has turned away for want of room.
func (f *Forwarder) Bridges() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bridges
}

func (f *Forwarder) BridgesRefused() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refused
}

// bridge dials the guest on behalf of one host connection and copies bytes.
func (f *Forwarder) bridge(host net.Conn, guestIP net.IP, guestPort uint16) {
	defer f.dropBridge()
	defer host.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// We appear to the guest as the gateway address, which is the only
	// address of ours the guest can route back to.
	local := nsnet.Full(f.nic, f.srcIP(), 0)
	remote := nsnet.Full(f.nic, guestIP, guestPort)
	guest, err := gonet.DialTCPWithBind(ctx, f.stk, local, remote, header.IPv4ProtocolNumber)
	if err != nil {
		f.log.Debug("forward: dial guest", "guest", remote.Addr, "err", err)
		return
	}
	defer guest.Close()

	f.log.Debug("forward: tcp connected", "host", host.RemoteAddr(), "guest", net.JoinHostPort(guestIP.String(), strconv.Itoa(int(guestPort))))
	nsnet.Splice(host, guest, f.log, "forward", "host", "guest")
}

// ForwardUDP listens on hostAddr on the host and relays datagrams to
// guestIP:guestPort. Like QEMU's hostfwd, the guest is only reachable from the
// peer that last sent a datagram, because the guest side socket is connected.
func (f *Forwarder) ForwardUDP(hostAddr string, guestIP net.IP, guestPort uint16) error {
	pc, err := net.ListenPacket("udp", hostAddr)
	if err != nil {
		return err
	}
	f.mu.Lock()
	if f.stopped {
		f.mu.Unlock()
		_ = pc.Close()
		return errors.New("svc: forwarder stopped")
	}
	f.conns = append(f.conns, pc)
	f.mu.Unlock()

	local := nsnet.Full(f.nic, f.srcIP(), 0)
	remote := nsnet.Full(f.nic, guestIP, guestPort)
	guest, terr := gonet.DialUDP(f.stk, &local, &remote, header.IPv4ProtocolNumber)
	if terr != nil {
		_ = pc.Close()
		return terr
	}

	f.log.Info("forward: udp", "host", pc.LocalAddr(), "guest", net.JoinHostPort(guestIP.String(), strconv.Itoa(int(guestPort))))
	go f.relayUDP(pc, guest)
	return nil
}

// relayUDP moves datagrams between the host socket and the connected guest
// socket. Two goroutines share one peer record: whatever host endpoint sent
// last is where guest replies go.
func (f *Forwarder) relayUDP(pc net.PacketConn, guest *gonet.UDPConn) {
	// Whichever direction notices first, both sockets close: the reader would
	// otherwise sit in Read until the stack released the guest's socket, which
	// is a goroutine and a host socket held for a guest that is not there.
	defer pc.Close()
	defer guest.Close()

	var (
		mu   sync.Mutex
		peer net.Addr
	)
	setPeer := func(a net.Addr) {
		mu.Lock()
		peer = a
		mu.Unlock()
	}
	getPeer := func() net.Addr {
		mu.Lock()
		defer mu.Unlock()
		return peer
	}

	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := guest.Read(buf)
			if err != nil {
				return
			}
			to := getPeer()
			if to == nil {
				continue
			}
			if _, err := pc.WriteTo(buf[:n], to); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			f.mu.Lock()
			stopped := f.stopped
			f.mu.Unlock()
			if !stopped {
				f.log.Debug("forward: udp read", "err", err)
			}
			return
		}
		setPeer(from)
		if _, err := guest.Write(buf[:n]); err != nil {
			f.log.Debug("forward: udp to guest", "err", err)
			return
		}
	}
}

// srcIP is the address the gateway dials from. It is set once by the engine.
func (f *Forwarder) srcIP() net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.src
}

// SetSourceIP chooses the gateway address used as the source of forwarded
// connections; it must be an address the guest can route back to.
func (f *Forwarder) SetSourceIP(ip net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.src = ip
}
