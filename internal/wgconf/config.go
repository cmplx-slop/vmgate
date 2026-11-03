package wgconf

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// DefaultMTU is the MTU wg-quick gives a tunnel, and what vmgate assumes
// when the file does not say.
const DefaultMTU = 1420

// The MTU a tunnel file may ask for. The lower bound is the smallest MTU an
// IPv4 tunnel is normally built with; the upper one is ours rather than wg's:
// every inner packet the peer sends is copied into the stack's queue, so a
// 64 KiB "MTU" turns one authenticated peer into tens of megabytes held here.
// What the guest is finally told is the smaller of this and the link MTU the
// gateway was configured with, which engine.lowerMTU works out.
const (
	minTunnelMTU = 1280
	maxTunnelMTU = 1500
)

// Config is a parsed and validated tunnel configuration.
type Config struct {
	// PrivateKey is the tunnel's curve25519 private key, 32 raw bytes.
	PrivateKey []byte

	// ListenPort is where the tunnel receives. 0 lets the host choose.
	ListenPort int

	// Addresses are the tunnel's own addresses, as written in Address=.
	Addresses []netip.Prefix

	// DNS are the resolvers the file names, in order. They are asked through
	// the tunnel, which makes them what the guest's lookups end up using.
	DNS []net.IP

	// MTU is the tunnel's MTU, DefaultMTU when the file is silent.
	MTU int

	// Peers holds the one peer the tunnel talks to.
	Peers []Peer
}

// Peer is the other end of the tunnel.
type Peer struct {
	// PublicKey is 32 raw bytes.
	PublicKey []byte

	// PreSharedKey is the optional symmetric key mixed into the handshake.
	PreSharedKey []byte

	// Endpoint is "host:port" as written; ResolveEndpoints turns a name into
	// an address. Empty means the peer has to dial in, which a gateway that
	// reaches out cannot use to reach anything.
	Endpoint string

	// EndpointName is the name ResolveEndpoints turned into Endpoint, and is
	// empty when the file wrote an address. Keeping it is worth one field:
	// that lookup is answered by the host, which makes it the one query in
	// this program that does not go through the tunnel, and an operator
	// comparing a name against what it answered is how a wrong address gets
	// noticed.
	EndpointName string

	// AllowedIPs is the peer's route list: the destinations that go through
	// the tunnel. Anything else has no route and is refused.
	AllowedIPs []netip.Prefix

	// Keepalive is PersistentKeepalive in seconds; 0 means off.
	Keepalive int
}

// Validate checks what the tunnel would otherwise discover in the middle of a
// connection: missing keys, no IPv4 address, a peer that carries nothing.
func (c *Config) Validate() error {
	if len(c.PrivateKey) != 32 {
		return errors.New("no PrivateKey in [Interface]")
	}
	if c.TunnelIP() == nil {
		return errors.New("[Interface] Address has no IPv4 address, and the gateway routes IPv4")
	}
	if len(c.Peers) == 0 {
		return errors.New("no [Peer] in the file")
	}
	if c.MTU < 1280 || c.MTU > 1500 {
		// The parser already refuses an out of range MTU in a file; this is the
		// same rule for a Config assembled some other way, and the tunnel wants
		// to believe it before handing the number to wireguard-go as the size
		// of every buffer it will hold.
		return fmt.Errorf("mtu %d is out of range (1280-1500)", c.MTU)
	}
	if len(c.Peers) > 1 {
		return fmt.Errorf("%d peers given; the gateway serves exactly one", len(c.Peers))
	}
	peer := c.Peers[0]
	if len(peer.PublicKey) != 32 {
		return errors.New("[Peer] PublicKey is missing")
	}
	if isZero(peer.PublicKey) {
		return errors.New("[Peer] PublicKey is all zeroes")
	}
	if own := c.PublicKey(); own != nil && bytesEqual(own, peer.PublicKey) {
		return errors.New("[Peer] PublicKey is the tunnel's own key")
	}
	if len(c.V4Routes()) == 0 {
		return errors.New("[Peer] AllowedIPs has no IPv4 prefix, so the tunnel would carry nothing")
	}
	return nil
}

// CheckInterfaceAddress rejects the addresses that cannot belong to an
// interface. A vpn.conf is often borrowed from somewhere else, and an interface
// address of 0.0.0.0 is the kind of thing that turns a typo into a strange
// afternoon; the same rule is worth applying to an address handed to a tunnel
// after it started.
func CheckInterfaceAddress(a netip.Addr) error {
	bcast := netip.AddrFrom4([4]byte{255, 255, 255, 255})
	switch {
	case a.IsUnspecified():
		return errors.New("is not a unicast address")
	case a.IsMulticast():
		return errors.New("is multicast, which no interface can own")
	case a == bcast:
		return errors.New("is the broadcast address")
	case a.IsLoopback():
		return errors.New("is a loopback address, which the gateway also answers for itself")
	}
	return nil
}

// checkAddress is the same rule, read off a prefix as a file writes it.
func checkAddress(p netip.Prefix) error {
	return CheckInterfaceAddress(p.Addr())
}
