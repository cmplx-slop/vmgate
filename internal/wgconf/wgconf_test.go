package wgconf

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// keypair returns a base64 private key and its base64 public key, the way wg
// prints both.
func keypair(t *testing.T) (priv, pub string) {
	t.Helper()

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// wg genkey clamps the scalar before printing it; do the same so the keys
	// look like the ones an operator would paste in.
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64

	var p [32]byte
	curve25519.ScalarBaseMult(&p, &raw)
	return base64.StdEncoding.EncodeToString(raw[:]), base64.StdEncoding.EncodeToString(p[:])
}

// pubOf derives the base64 public key of a base64 private key.
func pubOf(t *testing.T, priv string) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var p, k [32]byte
	copy(k[:], raw)
	curve25519.ScalarBaseMult(&p, &k)
	return base64.StdEncoding.EncodeToString(p[:])
}

const sampleConf = `
# a gateway's tunnel, in the shape wg-quick takes
[Interface]
PrivateKey  = %s
Address     = 10.6.0.2/32, fd00::2/128
DNS         = 10.6.0.1, 1.1.1.1
ListenPort  = 51820
MTU         = 1420
Table       = auto            # wg-quick's kernel instructions, ignored here
PreUp       = echo up
PostUp      = iptables -t nat -F
PreDown     = echo down
PostDown    = echo gone
PreDisconnect = echo losing
SaveConfig  = true
Fwmark      = 42

[Peer]
PublicKey   = %s
Endpoint    = vpn.example.net:51820
AllowedIPs  = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseSample(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)

	c, err := Parse("vpn.conf", strings.NewReader(fmt.Sprintf(sampleConf, priv, peerPub)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(c.PrivateKey) != 32 {
		t.Errorf("private key is %d bytes, want 32", len(c.PrivateKey))
	}
	if got := c.TunnelIP().String(); got != "10.6.0.2" {
		t.Errorf("tunnel address = %q, want 10.6.0.2", got)
	}
	if c.ListenPort != 51820 {
		t.Errorf("listen port = %d", c.ListenPort)
	}
	if c.MTU != 1420 {
		t.Errorf("mtu = %d", c.MTU)
	}
	if len(c.DNS) != 2 || c.DNS[0].String() != "10.6.0.1" {
		t.Errorf("dns = %v", c.DNS)
	}
	if len(c.Peers) != 1 {
		t.Fatalf("%d peers", len(c.Peers))
	}
	p := c.Peers[0]
	if base64.StdEncoding.EncodeToString(p.PublicKey) != peerPub {
		t.Error("peer public key did not survive the round trip")
	}
	if p.Endpoint != "vpn.example.net:51820" {
		t.Errorf("endpoint = %q", p.Endpoint)
	}
	if p.Keepalive != 25 {
		t.Errorf("keepalive = %d", p.Keepalive)
	}
	routes := c.V4Routes()
	if len(routes) != 1 || routes[0].String() != "0.0.0.0/0" {
		t.Errorf("v4 routes = %v, want [0.0.0.0/0]", routes)
	}
	if s := c.String(); s == "" || strings.Contains(s, base64.StdEncoding.EncodeToString(c.PrivateKey)) {
		t.Errorf("String() is empty or leaks the private key: %q", s)
	}
}

func TestDefaults(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)
	c, err := Parse("vpn.conf", strings.NewReader(strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.6.0.2",
		"[Peer]",
		"PublicKey = " + peerPub,
		"AllowedIPs = 10.0.0.0/8, 192.168.1.5",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.MTU != DefaultMTU {
		t.Errorf("mtu = %d, want the wg-quick default %d", c.MTU, DefaultMTU)
	}
	if c.ListenPort != 0 {
		t.Errorf("listen port = %d, want 0 (the host chooses)", c.ListenPort)
	}
	if len(c.DNS) != 0 {
		t.Errorf("dns = %v, want none", c.DNS)
	}
	// A bare address means a host route, and prefixes are stored masked.
	got := c.V4Routes()
	if len(got) != 2 || got[0].String() != "10.0.0.0/8" || got[1].String() != "192.168.1.5/32" {
		t.Errorf("v4 routes = %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)
	ownPub := pubOf(t, priv)
	shortKey := base64.StdEncoding.EncodeToString(make([]byte, 31))

	header := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\n"
	peer := "[Peer]\nPublicKey = " + peerPub + "\nAllowedIPs = 0.0.0.0/0\n"

	for _, tc := range []struct {
		name string
		text string
		want string
	}{
		{"no private key", "[Interface]\nAddress = 10.6.0.2/32\n" + peer, "PrivateKey"},
		{"key is not base64", "[Interface]\nPrivateKey = not-base64!\n", "base64"},
		{"key is the wrong length", "[Interface]\nPrivateKey = " + shortKey + "\n", "want 32"},
		{"no IPv4 address", "[Interface]\nPrivateKey = " + priv + "\nAddress = fd00::2/128\n", "IPv4"},
		{"unknown interface setting", header + "Cachet = on\n", "unknown interface setting"},
		{"unknown peer setting", header + "[Peer]\nPublicKey = " + peerPub + "\nAllowedIPs = 0.0.0.0/0\nNonsense = 1\n", "unknown peer setting"},
		{"unknown section", "[Tunnel]\nPrivateKey = " + priv + "\n", "unknown section"},
		{"setting before a section", "PrivateKey = " + priv + "\n", "before any"},
		{"two peers", header + peer + "[Peer]\nPublicKey = " + peerPub + "\nAllowedIPs = 10.0.0.0/8\n", "exactly one"},
		{"no peer", header, "no [Peer]"},
		{"peer key is our own", header + "[Peer]\nPublicKey = " + ownPub + "\nAllowedIPs = 0.0.0.0/0\n", "own key"},
		{"allowed ips are IPv6 only", header + "[Peer]\nPublicKey = " + peerPub + "\nAllowedIPs = ::/0\n", "no IPv4 prefix"},
		{"endpoint has no port", header + "[Peer]\nPublicKey = " + peerPub + "\nEndpoint = 198.51.100.7\nAllowedIPs = 0.0.0.0/0\n", "host:port"},
		{"dns entry is a name", "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\nDNS = resolver.example.net\n", "not an IP address"},
		{"private key twice", "[Interface]\nPrivateKey = " + priv + "\nPrivateKey = " + priv + "\n", "twice"},
		{"mtu out of range", "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\nMTU = 100\n", "mtu"},
		{"mtu larger than the tunnel may carry", "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\nMTU = 9000\n", "1280-1500"},
		{"address is not a host address", "[Interface]\nPrivateKey = " + priv + "\nAddress = 0.0.0.0/0\n", "not a unicast"},
		{"address is multicast", "[Interface]\nPrivateKey = " + priv + "\nAddress = 224.0.0.1/24\n", "multicast"},
		{"address is broadcast", "[Interface]\nPrivateKey = " + priv + "\nAddress = 255.255.255.255/32\n", "broadcast address"},
		{"address is loopback", "[Interface]\nPrivateKey = " + priv + "\nAddress = 127.0.0.1/32\n", "loopback"},
		{"line is not an assignment", "[Interface]\nthese are not a setting\n", "key = value"},
		{"value is empty", "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\nDNS =\n", "no value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse("vpn.conf", strings.NewReader(tc.text))
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error is %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestUAPI(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)
	psk := base64.StdEncoding.EncodeToString(make([]byte, 32))

	c, err := Parse("vpn.conf", strings.NewReader(strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.6.0.2/32",
		"ListenPort = 51820",
		"[Peer]",
		"PublicKey = " + peerPub,
		"PresharedKey = " + psk,
		"Endpoint = 198.51.100.7:51820",
		"AllowedIPs = 0.0.0.0/0, 10.6.0.1/32",
		"PersistentKeepalive = 25",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	uapi := c.UAPI()
	for _, want := range []string{
		"private_key=",
		"listen_port=51820",
		"replace_peers=true",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=10.6.0.1/32",
		"endpoint=198.51.100.7:51820",
		"persistent_keepalive_interval=25",
		"preshared_key=",
		"public_key=" + hexOf(pubRaw(t, peerPub)),
	} {
		if !strings.Contains(uapi, want) {
			t.Errorf("UAPI text has no %q:\n%s", want, uapi)
		}
	}
	if strings.Contains(uapi, base64.StdEncoding.EncodeToString(c.PrivateKey)) {
		t.Error("UAPI text carries the base64 private key; wg wants hex")
	}
}

func TestResolveEndpoints(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)
	c, err := Parse("vpn.conf", strings.NewReader(strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.6.0.2/32",
		"[Peer]",
		"PublicKey = " + peerPub,
		"Endpoint = vpn.example.net:51820",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	lookup := func(host string) ([]string, error) {
		if host != "vpn.example.net" {
			return nil, errors.New("no such host: " + host)
		}
		return []string{"fd00::1", "198.51.100.7"}, nil
	}
	if err := c.ResolveEndpoints(lookup); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got := c.Peers[0].Endpoint; got != "198.51.100.7:51820" {
		t.Errorf("endpoint = %q, want the IPv4 answer", got)
	}

	// An address is left alone: no resolver is needed to use one.
	c.Peers[0].Endpoint = "198.51.100.9:51820"
	if err := c.ResolveEndpoints(lookup); err != nil {
		t.Fatalf("literal endpoint: %v", err)
	}
	if c.Peers[0].Endpoint != "198.51.100.9:51820" {
		t.Errorf("literal endpoint became %q", c.Peers[0].Endpoint)
	}

	// A name with only AAAA records is a startup problem, not a tunnel that
	// quietly carries nothing.
	c.Peers[0].Endpoint = "vpn6.example.net:51820"
	only6 := func(string) ([]string, error) { return []string{"fd00::1"}, nil }
	if err := c.ResolveEndpoints(only6); err == nil {
		t.Error("want an error for a peer with no IPv4 address")
	}
}

// An interface address means the address: a wg-quick file writes 10.8.0.2/24 and
// means "this machine, on that network". AllowedIPs are the other way round, a
// prefix there is a network and the host bits are noise. The two used to share
// one parser, which turned 10.8.0.2/24 into an interface addressing the whole
// /24 and losing its own address on the way.
func TestAddressKeepsItsHostBits(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)

	c, err := Parse("vpn.conf", strings.NewReader(strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.6.0.2/24",
		"[Peer]",
		"PublicKey = " + peerPub,
		"AllowedIPs = 10.0.3.7/24",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := c.TunnelIP().String(); got != "10.6.0.2" {
		t.Errorf("tunnel address = %s, want the address as written", got)
	}
	if got := c.Addresses[0].String(); got != "10.6.0.2/24" {
		t.Errorf("address = %s, want its prefix length kept as well", got)
	}
	if got := c.V4Routes(); len(got) != 1 || got[0].String() != "10.0.3.0/24" {
		t.Errorf("routes = %v, want the network the entry names", got)
	}
}

// ListenPort = 0 is how a file says "let the host choose", the same as leaving
// the key out; the log names the port that was picked.
func TestListenPortZeroMeansTheHostChooses(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)

	c, err := Parse("vpn.conf", strings.NewReader(strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv,
		"Address = 10.6.0.2/32",
		"ListenPort = 0",
		"[Peer]",
		"PublicKey = " + peerPub,
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.ListenPort != 0 {
		t.Errorf("listen port = %d, want 0", c.ListenPort)
	}
	if u := c.UAPI(); strings.Contains(u, "listen_port") {
		t.Errorf("the configuration interface says %q, want no listen port at all", u)
	}
}

// A typo on a key line must not put the key in the error, the journal, or every
// bug report that follows.
func TestErrorsNeverCarryAKey(t *testing.T) {
	priv, _ := keypair(t)
	_, peerPub := keypair(t)
	psk := base64.StdEncoding.EncodeToString(make([]byte, 32))

	for _, text := range []string{
		"[Interface]\nPrivateKey = " + priv + "xx\n",
		"[Interface]\nPrivateKey = " + priv + "0\nAddress = 10.6.0.2/32\n",
		"[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = " + peerPub + "9\nAllowedIPs = 0.0.0.0/0\n",
		"[Interface]\nPrivateKey = " + priv + "\nAddress = 10.6.0.2/32\n[Peer]\nPublicKey = " + peerPub + "\nPresharedKey = " + psk + "9\nAllowedIPs = 0.0.0.0/0\n",
	} {
		_, err := Parse("vpn.conf", strings.NewReader(text))
		if err == nil {
			t.Fatal("a broken key was accepted")
		}
		if strings.Contains(err.Error(), priv) {
			t.Errorf("the error carries the private key: %v", err)
		}
		if strings.Contains(err.Error(), psk) {
			t.Errorf("the error carries the preshared key: %v", err)
		}
	}
}

// pubRaw decodes a base64 key so a test can compare it against the hex form the
// configuration interface wants.
func pubRaw(t *testing.T, b64 string) []byte {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return raw
}
