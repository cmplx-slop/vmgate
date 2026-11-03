package engine

import (
	"net"

	"vmgate/internal/config"
	"vmgate/internal/dns"
)

// resolverList is the tunnel configuration's resolvers in the form the DNS
// server relays to.
func resolverList(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, net.JoinHostPort(ip.String(), "53"))
	}
	return out
}

// Who named the resolvers, so a log line can say which one won and a test can
// insist on the order.
const (
	fileResolvers   = "dns.upstreams"
	tunnelResolvers = "vpn.conf"
	hostResolvers   = "the host"
)

// resolversFor chooses the servers a guest's lookups are forwarded to. The
// operator's dns.upstreams wins over the tunnel's DNS= entries: a VPN handing out
// a resolver the tunnel cannot reach is common enough that naming another has to
// be possible. Only when neither offers anything does the host's own list get
// used, and that is worth a warning rather than a debug line: those addresses are
// still asked from inside the tunnel, so one the tunnel cannot reach means no
// lookups answered at all.
func resolversFor(cfgDNS []string, tunnelDNS []net.IP) ([]string, string, error) {
	switch {
	case len(cfgDNS) > 0:
		out, err := dns.ParseResolvers(joinHosts(cfgDNS))
		if err != nil {
			return nil, "", err
		}
		return out, fileResolvers, nil
	case len(tunnelDNS) > 0:
		return resolverList(tunnelDNS), tunnelResolvers, nil
	default:
		return dns.SystemResolvers(), hostResolvers, nil
	}
}

// dnsList is the resolver list handed out by DHCP.
func dnsList(cfg config.Config) []net.IP {
	if cfg.DNSIP != nil {
		return []net.IP{cfg.DNSIP}
	}
	return []net.IP{cfg.GatewayIP}
}

func joinHosts(hosts []string) string {
	out := ""
	for i, h := range hosts {
		if i > 0 {
			out += ","
		}
		out += h
	}
	return out
}
