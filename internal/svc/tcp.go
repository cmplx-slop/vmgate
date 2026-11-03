package svc

import (
	"context"
	"net"
	"strconv"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/nsnet"
)

// ensureTCP creates the on-demand relay listener for dstIP:dstPort.
func (m *Manager) ensureTCP(dstIP net.IP, dstPort uint16, target Target) {
	k := mkKey(protoTCP, dstIP, dstPort)
	r := &relay{last: time.Now()}
	m.sweepRelays()

	m.mu.Lock()
	if m.stoppedLocked() || m.services[k] || m.relays[k] != nil || len(m.relays) >= m.maxRelays {
		m.mu.Unlock()
		return
	}
	m.relays[k] = r
	m.mu.Unlock()

	l, err := gonet.ListenTCP(m.stk, nsnet.Full(m.nic, dstIP, dstPort), header.IPv4ProtocolNumber)
	if err != nil {
		m.release(k, r)
		m.log.Debug("cannot listen for guest connection", "addr", k, "err", err)
		return
	}
	r.closer = l
	m.log.Debug("relay: tcp", "addr", k, "host", target.Addr)
	go m.acceptTCP(l, k, target, r)
}

// acceptTCP runs the life of one TCP listener. r is non-nil for an on-demand
// relay, whose slot is given back when the listener dies; nil means an explicit
// service, which lives as long as the gateway does.
func (m *Manager) acceptTCP(l *gonet.TCPListener, k key, target Target, r *relay) {
	defer nsnet.Guard(m.log, "tcp listener")
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			if m.isStopped() {
				return
			}
			m.release(k, r)
			m.log.Debug("internet: listener closed", "addr", k, "err", err)
			return
		}
		if r != nil {
			m.touch(k, r)
		}
		if ok, limit := m.addConn(conn); !ok {
			m.log.Debug("too many translations", "limit", limit, "guest", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		go m.handleTCP(conn, k, target, r)
	}
}

func (m *Manager) handleTCP(conn net.Conn, k key, target Target, r *relay) {
	defer nsnet.Guard(m.log, "tcp translation")
	defer conn.Close()
	defer m.dropConn(conn)

	// A target the operator named is dialled by the host. A destination the
	// guest chose goes through the tunnel, and only the tunnel.
	hostAddr := target.Addr
	viaHost := target.ViaHost()
	if !viaHost {
		// Original destination: the address the guest dialled, which is the
		// address this relay was created for.
		hostAddr = net.JoinHostPort(k.ip, strconv.Itoa(int(k.port)))
	}

	host, err := m.dialTCP(hostAddr, viaHost)
	if err != nil {
		if viaHost {
			m.log.Debug("tcp: host dial failed", "guest", conn.RemoteAddr(), "host", hostAddr, "err", err)
		} else {
			m.refusedDial("tcp", hostAddr, err)
		}
		return
	}
	defer host.Close()
	if viaHost {
		hostKeepAlive(host, m.tcpKeep)
	}

	name := target.Name
	if name == "" {
		name = "service"
	}
	m.log.Info(name+": tcp forward", "guest", conn.RemoteAddr(), "via", k.String(), "to", hostAddr)
	nsnet.Splice(conn, host, m.log, name, "guest", "host")
}

// dialTCP opens the far side of one TCP translation.
func (m *Manager) dialTCP(hostAddr string, viaHost bool) (net.Conn, error) {
	if viaHost {
		return m.dialer.Dial("tcp", hostAddr)
	}
	m.mu.Lock()
	tunnel, timeout := m.tunnel, m.dialTimeout
	m.mu.Unlock()

	if tunnel == nil {
		return nil, errNoTunnel
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return tunnel.DialTCP(ctx, hostAddr)
}
