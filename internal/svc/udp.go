package svc

import (
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"vmgate/internal/nsnet"
)

// ensureUDP creates the on-demand relay for dstIP:dstPort.
func (m *Manager) ensureUDP(dstIP net.IP, dstPort uint16, target Target) {
	k := mkKey(protoUDP, dstIP, dstPort)
	r := &relay{last: time.Now()}
	m.sweepRelays()

	m.mu.Lock()
	if m.stoppedLocked() || m.services[k] || m.relays[k] != nil || len(m.relays) >= m.maxRelays {
		m.mu.Unlock()
		return
	}
	m.relays[k] = r
	m.mu.Unlock()

	ep, err := nsnet.ListenUDP(m.stk, m.nic, dstIP, dstPort)
	if err != nil {
		m.release(k, r)
		m.log.Debug("cannot relay guest datagrams", "addr", k, "err", err)
		return
	}
	r.closer = ep
	m.log.Debug("relay: udp", "addr", k, "host", target.Addr)
	go m.pumpUDP(ep, k, target, r)
}

// pumpUDP moves datagrams from the guest onwards. Each guest socket gets its
// own path out, so an answer can be traced back to the guest endpoint that
// asked for it.
func (m *Manager) pumpUDP(ep *nsnet.UDP, k key, target Target, r *relay) {
	defer nsnet.Guard(m.log, "udp relay")
	defer ep.Close()

	var (
		mu    sync.Mutex
		paths = map[string]*udpPath{}
	)
	defer func() {
		mu.Lock()
		for _, p := range paths {
			_ = p.close()
		}
		mu.Unlock()
	}()

	buf := make([]byte, datagramBuf)
	for {
		n, from, err := ep.Read(buf)
		if err != nil {
			if m.isStopped() {
				return
			}
			m.release(k, r)
			m.log.Debug("udp: endpoint closed", "local", ep.LocalAddr(), "err", err)
			return
		}
		if from == nil || n == 0 {
			continue
		}
		if r != nil {
			m.touch(k, r)
		}
		hostAddr := target.Addr
		viaHost := target.ViaHost()
		if !viaHost {
			hostAddr = net.JoinHostPort(k.ip, strconv.Itoa(int(k.port)))
		}

		mu.Lock()
		path, ok := paths[from.String()]
		if !ok {
			// Give back the paths this guest stopped using before opening
			// another: one idiom with the relay table above, and no timer of
			// its own per relay.
			m.closeIdlePaths(paths)
		}
		if !ok && len(paths) >= m.maxPaths {
			// The guest invents its own source addresses, so the number of
			// paths one relay can open has to be bounded from here.
			mu.Unlock()
			m.log.Debug("udp: too many guest endpoints", "addr", k, "limit", m.maxPaths)
			continue
		}
		if !ok {
			if !m.takePath() {
				// One relay is bounded by maxPaths; the whole gateway has to
				// be bounded too, or relays times paths is what the host pays
				// for in sockets.
				mu.Unlock()
				m.log.Debug("udp: too many datagram paths", "limit", m.maxPathsTotal)
				continue
			}
			out, derr := m.openUDP(hostAddr, viaHost)
			if derr != nil {
				mu.Unlock()
				m.releasePath()
				if viaHost {
					m.log.Debug("udp: host path failed", "host", hostAddr, "err", derr)
				} else {
					m.refusedDial("udp", hostAddr, derr)
				}
				continue
			}
			path = &udpPath{
				out:  out,
				peer: from,
				ep:   ep,
				log:  m.log,
				idle: time.Now(),
			}
			paths[from.String()] = path
			go func() {
				defer nsnet.Guard(m.log, "udp path")
				path.run(func() {
					m.releasePath()
					mu.Lock()
					delete(paths, from.String())
					mu.Unlock()
				})
			}()
		}
		path.touch()
		mu.Unlock()

		if _, err := path.send(buf[:n]); err != nil {
			m.log.Debug("udp: forward failed", "host", hostAddr, "err", err)
		}
	}
}

// closeIdlePaths closes the paths the guest stopped using and drops them from
// the table. mu is held by the caller, which is how the relay loop and the
// goroutines reading each path take turns; closing a path only shuts its
// socket, and the reader does the rest of the bookkeeping when it gets the lock.
func (m *Manager) closeIdlePaths(paths map[string]*udpPath) {
	deadline := time.Now().Add(-m.udpIdle)
	for name, p := range paths {
		if p.lastSeen().Before(deadline) {
			p.close()
			delete(paths, name)
		}
	}
}

// hostPipe is a host datagram socket, used only for a target the operator
// named. A host PacketConn is not connected, so it satisfies Datagram the long
// way round: the destination is remembered here, and a datagram from anywhere
// else is dropped rather than handed to a guest as a reply. Pinning the peer is
// not a detail: a relay that would accept a datagram from anywhere lets any host
// on the network put bytes into a guest's flow without the guest having asked.
type hostPipe struct {
	pc net.PacketConn
	to *net.UDPAddr
}

func (p hostPipe) Write(b []byte) (int, error) { return p.pc.WriteTo(b, p.to) }

func (p hostPipe) Read(buf []byte) (int, error) {
	for {
		n, from, err := p.pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		ua, ok := from.(*net.UDPAddr)
		// Equal, not ==: an address from the kernel is four bytes and one from
		// ResolveUDPAddr is sixteen, and comparing them field by field would
		// throw away every reply the target sends.
		if !ok || ua.Port != p.to.Port || !ua.IP.Equal(p.to.IP) {
			continue
		}
		return n, nil
	}
}

func (p hostPipe) Close() error { return p.pc.Close() }

// openUDP starts the far side of one UDP relay. A destination the guest chose
// goes through the tunnel; only an endpoint the operator named is served by a
// host socket.
func (m *Manager) openUDP(hostAddr string, viaHost bool) (Datagram, error) {
	if viaHost {
		to, err := net.ResolveUDPAddr("udp", hostAddr)
		if err != nil {
			return nil, err
		}
		pc, err := m.dialer.ListenPacket("udp", "")
		if err != nil {
			return nil, err
		}
		return hostPipe{pc: pc, to: to}, nil
	}

	m.mu.Lock()
	tunnel := m.tunnel
	m.mu.Unlock()
	if tunnel == nil {
		return nil, errNoTunnel
	}
	return tunnel.DialUDP(hostAddr)
}

// udpPath is one guest socket translated onto one path out.
type udpPath struct {
	out  Datagram
	peer *net.UDPAddr
	ep   *nsnet.UDP
	log  *slog.Logger

	idle   time.Time
	idleMu sync.Mutex
	once   sync.Once
}

func (p *udpPath) touch() {
	p.idleMu.Lock()
	p.idle = time.Now()
	p.idleMu.Unlock()
}

func (p *udpPath) lastSeen() time.Time {
	p.idleMu.Lock()
	defer p.idleMu.Unlock()
	return p.idle
}

func (p *udpPath) close() error {
	var err error
	p.once.Do(func() { err = p.out.Close() })
	return err
}

func (p *udpPath) send(b []byte) (int, error) { return p.out.Write(b) }

// datagramBuf is the scratch one datagram is read into, in both directions of a
// relay. It is deliberately not the tunnel's MTU: a guest may send a larger
// datagram and have it fragmented, and the read takes the first datagramBuf
// bytes of whatever arrives rather than ending the relay, which is what nsnet
// does when its buffer is the smaller of the two.
const datagramBuf = 2048

// run copies answers back into the netstack towards the guest peer.
func (p *udpPath) run(gone func()) {
	buf := make([]byte, datagramBuf)
	for {
		n, err := p.out.Read(buf)
		if err != nil {
			gone()
			return
		}
		if n == 0 {
			continue
		}
		if _, err := p.ep.WriteTo(buf[:n], p.peer); err != nil {
			p.log.Debug("udp: reply failed", "to", p.peer, "err", err)
			gone()
			return
		}
	}
}
