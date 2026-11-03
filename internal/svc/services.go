package svc

import (
	"errors"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/nsnet"
)

// ServeTCP installs an explicit listener on one of our own addresses.
func (m *Manager) ServeTCP(bindIP net.IP, port uint16, target Target) error {
	k := mkKey(protoTCP, bindIP, port)
	m.mu.Lock()
	if m.stoppedLocked() {
		m.mu.Unlock()
		return ErrStopped
	}
	if m.services[k] || m.relays[k] != nil {
		m.mu.Unlock()
		return errors.New("svc: " + k.String() + " already served")
	}
	m.services[k] = true
	m.own[bindIP.String()] = true
	m.mu.Unlock()

	l, err := gonet.ListenTCP(m.stk, nsnet.Full(m.nic, bindIP, port), header.IPv4ProtocolNumber)
	if err != nil {
		return err
	}
	m.log.Info("service: tcp", "listen", k.String(), "host", target.Addr)
	go m.acceptTCP(l, k, target, nil)
	return nil
}

// ServeUDP installs an explicit relay on one of our own addresses.
func (m *Manager) ServeUDP(bindIP net.IP, port uint16, target Target) error {
	k := mkKey(protoUDP, bindIP, port)
	m.mu.Lock()
	if m.stoppedLocked() {
		m.mu.Unlock()
		return ErrStopped
	}
	if m.services[k] || m.relays[k] != nil {
		m.mu.Unlock()
		return errors.New("svc: " + k.String() + " already served")
	}
	m.services[k] = true
	m.own[bindIP.String()] = true
	m.mu.Unlock()

	ep, err := nsnet.ListenUDP(m.stk, m.nic, bindIP, port)
	if err != nil {
		return err
	}
	m.log.Info("service: udp", "listen", k.String(), "host", target.Addr)
	go m.pumpUDP(ep, k, target, nil)
	return nil
}

// ServeDNS answers datagrams on one of our addresses with handler, which is
// how the built-in DNS server is attached.
func (m *Manager) ServeDNS(bindIP net.IP, port uint16, handler QueryHandler) error {
	k := mkKey("udp", bindIP, port)
	m.mu.Lock()
	if m.stoppedLocked() {
		m.mu.Unlock()
		return ErrStopped
	}
	if m.services[k] || m.relays[k] != nil {
		m.mu.Unlock()
		return errors.New("svc: " + k.String() + " already served")
	}
	m.services[k] = true
	m.own[bindIP.String()] = true
	m.mu.Unlock()

	ep, err := nsnet.ListenUDP(m.stk, m.nic, bindIP, port)
	if err != nil {
		return err
	}
	m.log.Info("service: dns", "listen", k.String())
	go m.answerQueries(ep, handler)
	return nil
}

// dnsBuf is the largest query the gateway will read. A DNS message over UDP is
// 512 bytes by convention and 4096 by anything anyone actually sends; longer is
// truncated rather than refused, which is what nsnet's read does when the buffer
// is the smaller of the two.
const dnsBuf = 4096

// answerQueries is the request/response loop used by the DNS server.
func (m *Manager) answerQueries(ep *nsnet.UDP, handler QueryHandler) {
	defer nsnet.Guard(m.log, "dns service")
	defer ep.Close()
	buf := make([]byte, dnsBuf)
	for {
		n, from, err := ep.Read(buf)
		if err != nil {
			if m.isStopped() {
				return
			}
			m.log.Debug("dns: endpoint closed", "local", ep.LocalAddr(), "err", err)
			return
		}
		if from == nil || n == 0 {
			continue
		}
		reply, err := handler(buf[:n])
		if err != nil {
			m.log.Debug("dns: query failed", "from", from, "err", err)
			continue
		}
		if len(reply) == 0 {
			continue
		}
		if _, err := ep.WriteTo(reply, from); err != nil {
			m.log.Debug("dns: reply failed", "to", from, "err", err)
		}
	}
}
