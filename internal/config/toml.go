package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// File is the TOML shape of the configuration. Every field is optional: a blank
// one takes the built-in default when it is resolved, so a file only has to say
// what differs from the example. Load decodes every file over DefaultFile, so
// the switches that are on by default (dhcp.enabled, gateway.internet) only have
// to be written down to turn them off.
//
// examples/vmgate.toml is an annotated version of this.
type File struct {
	Link    Link      `toml:"link"`
	Network Network   `toml:"network"`
	DHCP    DHCP      `toml:"dhcp"`
	Gateway Gateway   `toml:"gateway"`
	DNS     DNS       `toml:"dns"`
	VPN     VPN       `toml:"vpn"`
	Log     Log       `toml:"log"`
	Forward []Forward `toml:"forward"`
	Service []Service `toml:"service"`
}

// Link says how the gateway joins QEMU's -netdev stream. Exactly one of listen
// and connect may be set: listen waits for QEMU to dial in, connect dials a
// QEMU that was started with server=on. Addresses are spelled unix:PATH or
// tcp:HOST:PORT, and a bare path is a unix socket.
type Link struct {
	Listen  string `toml:"listen"`
	Connect string `toml:"connect"`
}

// Network is the guest's network: the addresses the gateway answers for and
// the lease it hands out. MTU may be left out or 0, which means the default.
type Network struct {
	Gateway string `toml:"gateway"`
	DNSIP   string `toml:"dns_ip"`
	GuestIP string `toml:"guest_ip"`
	Netmask string `toml:"netmask"`
	MTU     uint   `toml:"mtu"`
	Domain  string `toml:"domain"`

	// MAC of the gateway; derived from the gateway address when empty.
	MAC string `toml:"mac"`

	// GuestMAC pins the lease and the inbound forwards to one client, which
	// is what makes a fixed forward to a guest address predictable.
	GuestMAC string `toml:"guest_mac"`
}

// DHCP is the built-in DHCP server.
type DHCP struct {
	Enabled   bool   `toml:"enabled"`
	LeaseTime string `toml:"lease_time"`

	// PoolSize is how many addresses past guest_ip may be leased.
	PoolSize int `toml:"pool_size"`
}

// Gateway is how the gateway treats traffic the guest sends to it, or through
// it, that is not covered by a [[service]].
type Gateway struct {
	// Internet lets the guest reach destinations of its own, through the
	// tunnel. With it off, the guest only reaches the gateway itself.
	Internet bool `toml:"internet"`

	// AllowEgress and DenyEgress say which destinations the guest may reach
	// once Internet is on. Each entry is an address or a CIDR; a bare prefix
	// length is refused, because allow_egress = ["0"] would mean everything.
	// The reserved ranges (loopback, link-local and the metadata
	// endpoint, multicast and the IANA special-purpose blocks) are always
	// denied unless allow_egress names them; private networks are allowed
	// unless deny_egress names them.
	AllowEgress []string `toml:"allow_egress"`
	DenyEgress  []string `toml:"deny_egress"`
}

// DNS is the gateway's resolver.
type DNS struct {
	// Upstreams are resolver addresses, optionally with a port. Left empty, the
	// ones named by DNS= in vpn.conf are used, and failing those the host's
	// own. They are asked through the tunnel, so they have to be reachable from
	// there; they have to be addresses, because the gateway has no resolver of
	// its own to ask before the tunnel exists.
	Upstreams []string `toml:"upstreams"`

	// MapHosts are names the resolver answers with the gateway address.
	MapHosts []string `toml:"map_hosts"`
}

// VPN names the tunnel that carries a guest's traffic. It has one setting
// because everything else about a tunnel belongs to the VPN: conf is a wg-quick
// configuration file, the shape wg-quick up takes, holding the keys, the tunnel
// address, the peer and its AllowedIPs, and optionally MTU and DNS.
//
// The file is read here and driven by wireguard-go inside this process, so
// there is no kernel interface, no TUN device and no change to the host's
// routes. The peer's AllowedIPs are the outer edge of what a guest can reach: a
// destination with no route through the tunnel is refused rather than sent the
// other way. conf is required; a relative path is read next to the
// configuration file.
type VPN struct {
	Conf string `toml:"conf"`
}

// Log is the diagnostics.
type Log struct {
	// Verbosity: 0 errors, 1 info, 2 debug.
	Verbosity int `toml:"verbosity"`

	// Sniff logs every packet crossing the link, in both directions.
	Sniff bool `toml:"sniff"`
}

// Forward is a host socket dialled into the guest.
type Forward struct {
	HostAddr  string `toml:"host_addr"` // default 127.0.0.1
	HostPort  uint16 `toml:"host_port"`
	GuestAddr string `toml:"guest_addr"` // default network.guest_ip
	GuestPort uint16 `toml:"guest_port"`
	Proto     string `toml:"proto"` // tcp (default) or udp
}

// Service is a port on the gateway that the host serves.
type Service struct {
	GuestPort uint16 `toml:"guest_port"`
	HostAddr  string `toml:"host_addr"` // default 127.0.0.1, names are resolved
	HostPort  uint16 `toml:"host_port"`
	Proto     string `toml:"proto"` // tcp (default) or udp
}

// Overrides are the settings the command line may still change, for the cases
// where the same guest definition has to run against a different socket or a
// different tunnel, or with debugging on. Setting one replaces whatever the file
// said, including the other end of the link: -connect on the command line turns
// a file that listens into a configuration that dials.
type Overrides struct {
	Listen  string
	Connect string

	// VPN names a different vpn.conf. A path given on the command line is read
	// where the shell said it is; a path in the file is read next to the file.
	VPN string

	Verbose *int
	Sniff   *bool
}

func (o Overrides) apply(f *File) {
	if o.Listen != "" {
		f.Link.Listen, f.Link.Connect = o.Listen, ""
	}
	if o.Connect != "" {
		f.Link.Connect, f.Link.Listen = o.Connect, ""
	}
	if o.VPN != "" {
		f.VPN.Conf = o.VPN
	}
	if o.Verbose != nil {
		f.Log.Verbosity = *o.Verbose
	}
	if o.Sniff != nil {
		f.Log.Sniff = *o.Sniff
	}
}

// DefaultFile is the file shape with the defaults that have a spelling in the
// file pre-filled, so decoding a file into it, or starting a hand built File
// from it, leaves every omitted setting at its default. The link address is not
// among them: whether the file said which end dials has to stay visible to
// Resolve, and the numeric settings that use 0 for "unset" (mtu, pool_size) are
// filled in by fillDefaults instead. DefaultFile is not a default configuration:
// there is none, because a tunnel always has to be named.
func DefaultFile() File {
	f := fillDefaults(File{})
	f.DHCP.Enabled = DefaultDHCP
	f.Gateway.Internet = DefaultInternet
	f.Log.Verbosity = DefaultVerbosity
	return f
}

// Load reads the TOML file at path, applies the overrides and resolves the
// result. A setting the file sets but the configuration does not have is an
// error, because a typo in a file is silent in a way a typo on the command line
// never is.
func Load(path string, ov Overrides) (Config, error) {
	if path == "" {
		return Config{}, errors.New("no configuration file: give -config PATH")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("configuration: %v", err)
	}

	f, err := parseTOML(path, string(data))
	if err != nil {
		return Config{}, err
	}

	// A vpn.conf named on the command line sits where the shell put it; one
	// named in the file sits next to the file. Either way it ends up absolute,
	// so the tunnel is found the same way from any working directory.
	if ov.VPN != "" {
		if ov.VPN, err = filepath.Abs(ov.VPN); err != nil {
			return Config{}, fmt.Errorf("vpn: conf: %v", err)
		}
	}
	ov.apply(&f)
	if f.VPN.Conf != "" && !filepath.IsAbs(f.VPN.Conf) {
		f.VPN.Conf = filepath.Join(filepath.Dir(path), f.VPN.Conf)
	}

	return Resolve(f)
}

// parseTOML decodes file text over the defaults.
func parseTOML(path, text string) (File, error) {
	f := DefaultFile()
	md, err := toml.Decode(text, &f)
	if err != nil {
		return f, fmt.Errorf("%s: %v", path, err)
	}
	if unknown := md.Undecoded(); len(unknown) > 0 {
		keys := make([]string, 0, len(unknown))
		for _, k := range unknown {
			keys = append(keys, strings.Join(k, "."))
		}
		return f, fmt.Errorf("%s: unknown setting: %s", path, strings.Join(keys, ", "))
	}
	return f, nil
}
