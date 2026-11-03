package wgconf

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// TunnelIP is the tunnel's IPv4 address, which becomes the source address of
// everything the guest sends through the tunnel.
func (c *Config) TunnelIP() net.IP {
	for _, p := range c.Addresses {
		if p.Addr().Is4() {
			return p.Addr().AsSlice()
		}
	}
	return nil
}

// PublicKey derives the tunnel's public key from its private key, so a file can
// be checked against itself and identified in the log the way wg does.
func (c *Config) PublicKey() []byte {
	if len(c.PrivateKey) != 32 {
		return nil
	}
	var pub, priv [32]byte
	copy(priv[:], c.PrivateKey)
	curve25519.ScalarBaseMult(&pub, &priv)
	return pub[:]
}

// V4Routes is the union of the peers' IPv4 AllowedIPs: the destinations with a
// route through the tunnel. Everything else the guest asks for has no route and
// is refused.
func (c *Config) V4Routes() []netip.Prefix {
	var out []netip.Prefix
	for _, peer := range c.Peers {
		for _, p := range peer.AllowedIPs {
			if p.Addr().Is4() {
				out = append(out, p)
			}
		}
	}
	return out
}

// RouteStrings is the same as V4Routes in the shape a log line wants.
func (c *Config) RouteStrings() []string {
	var out []string
	for _, p := range c.V4Routes() {
		out = append(out, p.String())
	}
	return out
}

// ResolveEndpoints turns each peer's endpoint name into an address using the
// host's resolver. That is control traffic, before the tunnel carries anything:
// reaching the peer is the only way the tunnel can work at all, and the name is
// looked up once here rather than per packet.
func (c *Config) ResolveEndpoints(lookup func(host string) ([]string, error)) error {
	if lookup == nil {
		lookup = net.LookupHost
	}
	for i := range c.Peers {
		p := &c.Peers[i]
		if p.Endpoint == "" {
			continue
		}
		host, port, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			return fmt.Errorf("peer endpoint %q is not host:port", p.Endpoint)
		}
		if net.ParseIP(host) != nil {
			continue
		}
		addrs, err := lookup(host)
		if err != nil || len(addrs) == 0 {
			return fmt.Errorf("peer endpoint %q cannot be resolved: %v", p.Endpoint, err)
		}
		var v4 string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				v4 = a
				break
			}
		}
		if v4 == "" {
			return fmt.Errorf("peer endpoint %q has no IPv4 address; the tunnel speaks IPv4", p.Endpoint)
		}
		p.EndpointName = host
		p.Endpoint = net.JoinHostPort(v4, port)
	}
	return nil
}

// UAPI renders the configuration the way wireguard-go's configuration interface
// takes it: keys in hex, one block per peer. It is the dialect `wg syncconf`
// speaks, only hex where wg uses base64.
func (c *Config) UAPI() string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hexOf(c.PrivateKey))
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	b.WriteString("replace_peers=true\n")
	for _, p := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hexOf(p.PublicKey))
		b.WriteString("replace_allowed_ips=true\n")
		for _, pre := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", pre.String())
		}
		if len(p.PreSharedKey) == 32 {
			fmt.Fprintf(&b, "preshared_key=%s\n", hexOf(p.PreSharedKey))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.Keepalive)
		}
	}
	return b.String()
}

// String is a rendering fit for a log line: enough to identify the tunnel, and
// never a private key.
func (c *Config) String() string {
	peer := Peer{}
	if len(c.Peers) == 1 {
		peer = c.Peers[0]
	}
	return fmt.Sprintf("address %s, mtu %d, peer %s, endpoint %s, v4 routes %d, dns %d",
		c.TunnelIP(), c.MTU, KeyString(peer.PublicKey), orNone(peer.Endpoint), len(c.V4Routes()), len(c.DNS))
}

// KeyString renders a key as wg does, base64. Only public keys belong here.
func KeyString(k []byte) string {
	if len(k) != 32 {
		return "(none)"
	}
	return base64.StdEncoding.EncodeToString(k)
}
