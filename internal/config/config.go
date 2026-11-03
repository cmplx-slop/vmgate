package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Package config reads a TOML configuration file, applies the few settings the
// command line may still override, and turns the result into the settings every
// other package needs.
//
// The file format is the File type in toml.go; examples/vmgate.toml is an
// annotated example. Only the QEMU socket, the tunnel's configuration file, the
// verbosity and the packet log can be set on the command line, because those are
// the settings that change between runs of the same guest.

// Default addresses follow the slirp/passt conventions, so existing guest
// images and documentation keep making sense:
//
//	10.0.2.2   gateway (vmgate itself)
//	10.0.2.3   DNS server handed out by DHCP
//	10.0.2.15  the lease handed to the guest
const (
	DefaultGateway  = "10.0.2.2"
	DefaultDNS      = "10.0.2.3"
	DefaultGuest    = "10.0.2.15"
	DefaultDomain   = "vmgate"
	DefaultNetmask  = "255.255.255.0"
	DefaultMTU      = 1500
	DefaultPoolSize = 16
)

// Defaults for the settings whose absence in a file means "on": the guest has
// no way to say so any other way, and turning them off is the unusual case.
const (
	DefaultDHCP      = true
	DefaultInternet  = true
	DefaultVerbosity = 1
)

// DefaultLease is how long a DHCP lease lasts unless the file says otherwise.
const DefaultLease = 24 * time.Hour

// Protocol is "tcp" or "udp".
type Protocol string

// Supported protocols.
const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// parseProtocol accepts "tcp", "udp" or "" (defaults to tcp).
func parseProtocol(s string) (Protocol, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	default:
		return "", fmt.Errorf("unknown protocol %q (want tcp or udp)", s)
	}
}

// Inbound is one resolved [[forward]]: a host listener spliced into the
// guest.
//
//	[[forward]]
//	host_port  = 2222
//	guest_port = 22
//
// lets "ssh localhost:2222" reach sshd in the guest on port 22.
type Inbound struct {
	Proto     Protocol
	HostAddr  string // listen address on the host, default 127.0.0.1
	HostPort  uint16
	GuestAddr net.IP
	GuestPort uint16
}

func (f Inbound) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d", f.Proto, f.HostAddr, f.HostPort, f.GuestAddr, f.GuestPort)
}

// Outbound is one resolved [[service]]: a port on the gateway that the
// guest reaches.
//
//	[[service]]
//	guest_port = 80
//	host_addr  = "127.0.0.1"
//	host_port  = 8080
//
// turns a guest connection to 10.0.2.2:80 into a connection to the HTTP server
// the host runs on 127.0.0.1:8080.
type Outbound struct {
	Proto     Protocol
	GuestPort uint16
	HostAddr  string
	HostPort  uint16
}

func (f Outbound) String() string {
	return fmt.Sprintf("%s gateway:%d -> %s:%d", f.Proto, f.GuestPort, f.HostAddr, f.HostPort)
}

// Config is the resolved configuration: every value validated and parsed, in
// the form the engine consumes.
type Config struct {
	// QEMU link.
	Listen  string
	Connect string

	// LinkDefault records that link.listen is ours rather than the operator's,
	// which decides how strictly its directory is checked: a path we chose has
	// to be private, one that was written down is the operator's business and
	// only gets a warning.
	LinkDefault bool

	// Guest network.
	GatewayIP net.IP
	DNSIP     net.IP
	GuestIP   net.IP
	MAC       net.HardwareAddr
	GuestMAC  net.HardwareAddr
	Mask      net.IPMask
	MTU       uint
	Domain    string

	// DHCP.
	DHCP      bool
	LeaseTime time.Duration
	PoolSize  int

	// Reachability.
	Internet   bool
	Egress     *EgressPolicy
	DNS        []string
	ExtraHosts map[string]net.IP

	// VPN is the wg-quick configuration file whose tunnel carries a guest's
	// traffic. It is required: a guest has no other way out, and a missing
	// file is refused at startup rather than answered with the host's own
	// connection.
	VPN string

	// The port forwards, in the order the file wrote them. Forwards are the
	// resolved [[forward]] sections and reach into the guest; Services are the
	// resolved [[service]] sections, which are what the guest reaches on the
	// gateway itself.
	Forwards []Inbound
	Services []Outbound

	// Diagnostics.
	Verbose      int
	SniffPackets bool
}

// PrefixLen returns the prefix length of Mask.
func (c *Config) PrefixLen() int {
	ones, _ := c.Mask.Size()
	return ones
}

// Subnet is the network the guest lives on. The gateway address and the mask
// are already in this config; handing them over as one value is what keeps the
// three places that need to know which addresses belong to the guest's own
// segment (the route table, the tunnel's addresses, and a guest's chosen
// destination) from each working out the network on their own.
func (c *Config) Subnet() *net.IPNet {
	return &net.IPNet{IP: c.GatewayIP.Mask(c.Mask), Mask: c.Mask}
}
