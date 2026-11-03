package dns

import (
	"log/slog"
	"net"
	"strings"
	"sync"

	"vmgate/internal/svc"
)

// Package dns implements the gateway's DNS server: it answers synthetic A
// records for hosts named in dns.map_hosts and relays everything else to an
// upstream resolver, which for a guest is a resolver asked from inside the VPN
// tunnel rather than over the host's own connection.
//
// Reading a query is left to x/net/dns/dnsmessage: it walks names, follows the
// compression pointers a client may use inside a question, and knows the length
// limits a label has to fit inside. Writing a reply is not, because a reply here
// is the query's question with one record bolted on and nothing else changed,
// which is a decision about bytes rather than about a data structure; dns.go
// spells it out.

// Server answers DNS queries from the gateway.
type Server struct {
	mu    sync.Mutex
	hosts map[string]net.IP
	up    resolver
	log   *slog.Logger
}

// New returns a DNS server relaying to up.
func New(up resolver, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{hosts: make(map[string]net.IP), up: up, log: log}
}

// AddHost registers a synthetic A record.
func (s *Server) AddHost(name string, ip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts[strings.ToLower(strings.TrimSuffix(name, "."))] = ip
}

// Hosts returns the number of configured mappings.
func (s *Server) HostCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hosts)
}

func (s *Server) lookup(name string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ip, ok := s.hosts[strings.ToLower(strings.TrimSuffix(name, "."))]
	return ip, ok
}

// ServeQuery handles one query and returns the response to send back, or nil
// if nothing should be sent. It satisfies svc.QueryHandler.
func (s *Server) ServeQuery(msg []byte) ([]byte, error) {
	q, err := ParseQuestion(msg)
	if err != nil {
		return nil, err
	}
	if ip, ok := s.lookup(q.Name); ok {
		if q.Type == TypeA {
			return q.answer(ip), nil
		}
		// Known name, unsupported type: reply with NOERROR and no answers.
		return q.noAnswer(), nil
	}
	if s.up == nil {
		return q.nxdomain(), nil
	}
	resp, err := s.up.Exchange(msg)
	if err != nil {
		s.log.Debug("dns: upstream", "err", err)
		return q.nxdomain(), nil
	}
	return resp, nil
}

// Register attaches the server to the gateway stack on each of the given
// addresses, which are the addresses the guest is told to use as resolvers.
func (s *Server) Register(mgr *svc.Manager, port uint16, ips ...net.IP) error {
	for _, ip := range ips {
		if err := mgr.ServeDNS(ip, port, s.ServeQuery); err != nil {
			return err
		}
	}
	return nil
}
