package dhcp

import (
	"net"
	"time"
)

// replyTo decides between a broadcast and a unicast reply. A client that has
// no address yet cannot receive unicast traffic, so its broadcast flag is
// honoured, and broadcast is the fallback whenever the request arrived from
// an unspecified source address.
func (s *Server) replyTo(req *Message, from *net.UDPAddr) *net.UDPAddr {
	const clientPort = 68
	if req.ClientIP != nil && !req.ClientIP.IsUnspecified() {
		return &net.UDPAddr{IP: req.ClientIP, Port: clientPort}
	}
	if req.Flags&FlagBroadcast == 0 && from != nil && from.IP != nil && !from.IP.IsUnspecified() {
		return from
	}
	return &net.UDPAddr{IP: net.IPv4bcast, Port: clientPort}
}

// Handle runs the DHCP state machine for one request and returns the reply.
func (s *Server) Handle(req *Message) (*Message, bool) {
	if req.Op != OpBootpRequest {
		return nil, false
	}
	mac := req.HardwareAddress()
	if len(mac) == 0 {
		return nil, false
	}
	if s.cfg.PinMAC != nil && mac.String() != s.cfg.PinMAC.String() {
		if s.cfg.Logger != nil {
			s.cfg.Logger.Debug("dhcp ignoring unpinned client", "mac", mac)
		}
		return nil, false
	}

	msgType := req.Type()
	if s.cfg.Logger != nil {
		s.cfg.Logger.Info("dhcp request", "msg", TypeString(msgType), "mac", mac, "xid", req.XID)
	}

	switch msgType {
	case Discover:
		// With nothing to offer there is no answer. An OFFER carrying no address
		// is a message the client cannot use, and it only invites a REQUEST that
		// can be answered no better than with a NAK.
		lease := s.allocate(mac, nil)
		if lease == nil {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Debug("dhcp has nothing to offer", "mac", mac,
					"pool", s.cfg.Pool.Size)
			}
			return nil, false
		}
		return s.reply(req, Offer, lease), true
	case Request:
		want := req.Options.IP(OptRequestedIP)
		lease := s.allocate(mac, want)
		if lease == nil {
			return s.nak(req), true
		}
		if want != nil && !want.IsUnspecified() && !want.Equal(lease.IP) {
			return s.nak(req), true
		}
		return s.reply(req, Ack, lease), true
	case Decline, Release:
		s.release(mac)
		return nil, false
	case Inform:
		return s.reply(req, Ack, nil), true
	default:
		return nil, false
	}
}

// allocate returns the lease for mac, honouring a requested address.
func (s *Server) allocate(mac net.HardwareAddr, want net.IP) *Lease {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := mac.String()
	now := s.now()
	if l, ok := s.byMAC[key]; ok {
		if want == nil || want.IsUnspecified() || want.Equal(l.IP) {
			if now.After(l.Expiry) {
				l.Expiry = now.Add(s.cfg.LeaseTime)
			}
			return l
		}
		// This client is asking for something else; its old address goes back.
		s.drop(key)
	}

	ip := want
	if ip != nil && !ip.IsUnspecified() {
		// A requested address cannot make the table grow: taking one means
		// giving it up by whoever held it.
		if !s.cfg.Pool.Contains(ip) || s.held(ip, key, now) {
			return nil
		}
	} else {
		if len(s.byMAC) >= s.maxLeases() {
			s.sweep(now)
		}
		if len(s.byMAC) >= s.maxLeases() {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Warn("dhcp lease table full", "mac", mac, "limit", s.maxLeases())
			}
			return nil
		}
		if ip = s.freeAddress(key, now); ip == nil {
			return nil
		}
	}

	l := &Lease{Client: mac, IP: ip, Expiry: now.Add(s.cfg.LeaseTime)}
	if holder, ok := s.byIP[l.IP.String()]; ok && holder != key {
		delete(s.byMAC, holder)
	}
	s.byMAC[key] = l
	s.byIP[l.IP.String()] = key
	return l
}

// held reports whether another client still has this address. A lease whose time
// has passed is not held: it is removed here, which is what stops the table
// filling up with assignments nobody has.
func (s *Server) held(ip net.IP, skipKey string, now time.Time) bool {
	holder, ok := s.byIP[ip.String()]
	if !ok || holder == skipKey {
		return false
	}
	l, ok := s.byMAC[holder]
	if !ok {
		delete(s.byIP, ip.String())
		return false
	}
	if now.Before(l.Expiry) {
		return true
	}
	s.drop(holder)
	return false
}

// freeAddress picks a usable pool address: reserved addresses such as the
// gateway, the DNS address and the network address are skipped, as are addresses
// a live lease still holds. The search starts where the last one stopped, so a
// pool of thousands is not walked from the beginning for every client.
func (s *Server) freeAddress(key string, now time.Time) net.IP {
	reserved := append([]net.IP{s.cfg.Gateway}, s.cfg.DNS...)
	size := s.cfg.Pool.Size
	for n := 0; n < size; n++ {
		i := (s.next + n) % size
		ip := s.cfg.Pool.At(i)

		bad := false
		for _, r := range reserved {
			if r != nil && r.Equal(ip) {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		if ip.Mask(s.cfg.Mask).Equal(ip) {
			continue // the network address
		}
		if s.held(ip, key, now) {
			continue
		}
		s.next = (i + 1) % size
		return ip
	}
	return nil
}

// maxLeases is how many leases the table may hold. There can only ever be one
// live lease per pool address, so the pool is the bound: past that, what is
// filling the table is clients asking again with a new hardware address, and a
// table bigger than the pool makes every later request a longer search.
func (s *Server) maxLeases() int {
	if s.cfg.Pool.Size < 1 {
		return 1
	}
	return s.cfg.Pool.Size
}

// sweep forgets every lease whose time has passed. It runs when the table is
// full, which is the only moment its size costs anything.
func (s *Server) sweep(now time.Time) {
	for key, l := range s.byMAC {
		if !now.Before(l.Expiry) {
			s.drop(key)
		}
	}
}

// drop forgets one lease, in both indexes.
func (s *Server) drop(key string) {
	if l, ok := s.byMAC[key]; ok {
		if s.byIP[l.IP.String()] == key {
			delete(s.byIP, l.IP.String())
		}
		delete(s.byMAC, key)
	}
}

func (s *Server) release(mac net.HardwareAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drop(mac.String())
}

func (s *Server) reply(req *Message, msgType byte, lease *Lease) *Message {
	rep := &Message{
		Op:       OpBootpReply,
		HType:    1,
		HLen:     byte(len(req.CHAddr)),
		XID:      req.XID,
		Flags:    req.Flags,
		ServerIP: s.cfg.Gateway,
		CHAddr:   req.CHAddr,
		SName:    s.cfg.Domain,
	}
	if lease != nil {
		rep.YourIP = lease.IP
	}
	rep.Options.Set(OptMessageType, []byte{msgType})
	rep.Options.Set(OptServerID, encodeIPs(s.cfg.Gateway))
	if lease != nil {
		rep.Options.Set(OptLeaseTime, encodeUint32(uint32(s.cfg.LeaseTime/time.Second)))
		rep.Options.Set(OptRenewalTime, encodeUint32(uint32(s.cfg.RenewTime/time.Second)))
		rep.Options.Set(OptRebindTime, encodeUint32(uint32(s.cfg.RebindTime/time.Second)))
		rep.Options.Set(OptRequestedIP, encodeIPs(lease.IP))
	}
	if s.cfg.Mask != nil {
		rep.Options.Set(OptSubnetMask, encodeIPs(net.IP(s.cfg.Mask)))
	}
	if s.cfg.Gateway != nil {
		rep.Options.Set(OptRouter, encodeIPs(s.cfg.Gateway))
	}
	if len(s.cfg.DNS) > 0 {
		rep.Options.Set(OptDNS, encodeIPs(s.cfg.DNS...))
	}
	if s.cfg.Domain != "" {
		rep.Options.Set(OptDomainName, []byte(s.cfg.Domain))
	}
	if s.cfg.MTU >= 68 && s.cfg.MTU != 1500 {
		rep.Options.Set(OptInterfaceMTU, []byte{byte(s.cfg.MTU >> 8), byte(s.cfg.MTU)})
	}
	return rep
}

func (s *Server) nak(req *Message) *Message {
	rep := &Message{
		Op:       OpBootpReply,
		HType:    1,
		HLen:     byte(len(req.CHAddr)),
		XID:      req.XID,
		Flags:    req.Flags | FlagBroadcast,
		ServerIP: s.cfg.Gateway,
		CHAddr:   req.CHAddr,
	}
	rep.Options.Set(OptMessageType, []byte{Nak})
	rep.Options.Set(OptServerID, encodeIPs(s.cfg.Gateway))
	return rep
}
