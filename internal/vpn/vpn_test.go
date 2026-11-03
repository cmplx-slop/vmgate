package vpn

import (
	"net/netip"
	"strings"
	"testing"

	"vmgate/internal/wgconf"
)

// A tunnel is built from a configuration that has already been checked, and
// says so: the rest of New reaches for the peer, the address and the MTU without
// looking, so a hand-built Config missing one of them would be a panic in a
// gateway that should have refused to start.
func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 1
	addr := []netip.Prefix{netip.MustParsePrefix("10.76.0.2/32")}
	peer := []wgconf.Peer{{PublicKey: key}}

	for _, tc := range []struct {
		name string
		conf *wgconf.Config
		want string
	}{
		{"nothing at all", &wgconf.Config{}, "PrivateKey"},
		{"no peer", &wgconf.Config{PrivateKey: key, Addresses: addr, MTU: 1420}, "[Peer]"},
		{"no IPv4 address", &wgconf.Config{PrivateKey: key, MTU: 1420, Peers: peer}, "Address"},
		{"mtu larger than a tunnel may carry",
			&wgconf.Config{PrivateKey: key, Addresses: addr, MTU: 9000, Peers: peer}, "1280-1500"},
		{"no route for the tunnel to carry",
			&wgconf.Config{PrivateKey: key, Addresses: addr, MTU: 1420, Peers: peer}, "AllowedIPs"},
	} {
		_, err := New(tc.conf, nil)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: failed with %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}
