package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Resolve validates a file configuration and turns it into a Config. Blank
// fields take the built-in defaults, and a 0 in a numeric setting means the
// same as leaving it out, so a File that starts from DefaultFile is as usable
// as one read from disk.
//
// The work is split one function per section of the file, so that reading the
// rules for [network] does not mean holding the rules for [dhcp] as well, and
// every error already names the key it is about.
func Resolve(f File) (Config, error) {
	f = fillDefaults(f)

	var c Config
	if err := resolveLink(&f, &c); err != nil {
		return c, err
	}
	if err := resolveNetwork(&f, &c); err != nil {
		return c, err
	}
	if err := resolveDHCP(&f, &c); err != nil {
		return c, err
	}
	if err := resolveVPN(&f, &c); err != nil {
		return c, err
	}
	if err := resolveGateway(&f, &c); err != nil {
		return c, err
	}
	if err := resolveDNS(&f, &c); err != nil {
		return c, err
	}
	if err := resolveTables(&f, &c); err != nil {
		return c, err
	}

	c.Verbose = f.Log.Verbosity
	c.SniffPackets = f.Log.Sniff
	return c, nil
}

// resolveLink decides which end of the QEMU connection dials. Nothing saying
// so is a choice of its own: wait for QEMU on a private socket named after the
// guest.
func resolveLink(f *File, c *Config) error {
	if f.Link.Listen != "" && f.Link.Connect != "" {
		return errors.New("link: listen and connect cannot both be set")
	}
	defaulted := false
	if f.Link.Listen == "" && f.Link.Connect == "" {
		f.Link.Listen = "unix:" + defaultSocketPath(f.Network.GuestIP)
		defaulted = true
	}
	c.Listen, c.Connect = f.Link.Listen, f.Link.Connect
	// Where the socket path came from decides how strictly its directory is
	// checked: ours have to be private, one the operator wrote down is their
	// own business.
	c.LinkDefault = defaulted
	return nil
}

// resolveNetwork parses the addresses the guest is given, the link address the
// gateway uses, and the ceiling on a frame.
func resolveNetwork(f *File, c *Config) error {
	var err error
	if c.GatewayIP, err = parseIP("network.gateway", f.Network.Gateway); err != nil {
		return err
	}
	if c.GuestIP, err = parseIP("network.guest_ip", f.Network.GuestIP); err != nil {
		return err
	}
	if f.Network.DNSIP != "" {
		if c.DNSIP, err = parseIP("network.dns_ip", f.Network.DNSIP); err != nil {
			return err
		}
	}
	if c.Mask, err = parseMask("network.netmask", f.Network.Netmask); err != nil {
		return err
	}

	if f.Network.MAC != "" {
		if c.MAC, err = parseMAC("network.mac", f.Network.MAC); err != nil {
			return err
		}
	} else {
		c.MAC = deriveMAC(c.GatewayIP)
	}
	if f.Network.GuestMAC != "" {
		if c.GuestMAC, err = parseMAC("network.guest_mac", f.Network.GuestMAC); err != nil {
			return err
		}
	}

	// The only ceiling here is what an interface can carry. What the guest is
	// told is the smaller of this and the tunnel's MTU, which engine.lowerMTU
	// works out once the tunnel file has been read.
	if f.Network.MTU == 0 || f.Network.MTU > 65535 {
		return fmt.Errorf("network: mtu %d out of range", f.Network.MTU)
	}
	c.MTU = f.Network.MTU
	c.Domain = f.Network.Domain
	return nil
}

// resolveDHCP parses the lease pool. Whether the server runs at all is the one
// boolean the file has for it.
func resolveDHCP(f *File, c *Config) error {
	c.DHCP = f.DHCP.Enabled
	lease, err := parseDuration("dhcp.lease_time", f.DHCP.LeaseTime)
	if err != nil {
		return err
	}
	if lease < time.Minute {
		return fmt.Errorf("dhcp: lease_time %v is too short to hand out", lease)
	}
	c.LeaseTime = lease
	if f.DHCP.PoolSize <= 0 || f.DHCP.PoolSize > 4096 {
		return fmt.Errorf("dhcp: pool_size %d out of range", f.DHCP.PoolSize)
	}
	c.PoolSize = f.DHCP.PoolSize
	return nil
}

// resolveVPN finds the tunnel configuration. The tunnel is not optional. A
// gateway that quietly fell back to the host's connection because a vpn.conf
// was missing, or misspelled, would be a gateway that leaks a guest's traffic
// over a typo.
func resolveVPN(f *File, c *Config) error {
	c.VPN = strings.TrimSpace(f.VPN.Conf)
	if c.VPN == "" {
		return errors.New("vpn: conf is required: a guest's traffic is routed through a tunnel, so name a wg-quick configuration file")
	}
	if _, err := os.Stat(c.VPN); err != nil {
		return fmt.Errorf("vpn: conf: %v", err)
	}
	return nil
}

// resolveGateway parses what a guest may reach beyond the gateway: the switch
// that lets it reach anything, and the two lists that narrow it again.
func resolveGateway(f *File, c *Config) error {
	c.Internet = f.Gateway.Internet
	egress, err := ParseEgress(f.Gateway.AllowEgress, f.Gateway.DenyEgress)
	if err != nil {
		return err
	}
	c.Egress = egress
	return nil
}

// resolveDNS parses the resolvers the gateway will ask, and the names it
// answers with its own address.
func resolveDNS(f *File, c *Config) error {
	for _, entry := range f.DNS.Upstreams {
		if err := checkResolver(entry); err != nil {
			return err
		}
		c.DNS = append(c.DNS, entry)
	}

	c.ExtraHosts = map[string]net.IP{}
	for _, name := range f.DNS.MapHosts {
		name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if name == "" {
			return errors.New("dns: map_hosts has an empty name")
		}
		c.ExtraHosts[name] = c.GatewayIP
	}
	return nil
}

// resolveTables reads the [[forward]] and [[service]] entries. The forward
// entries default their guest address to the first lease, which is why they
// come after [network].
func resolveTables(f *File, c *Config) error {
	for i, fwd := range f.Forward {
		in, err := resolveForward(fwd, i+1, c.GuestIP)
		if err != nil {
			return err
		}
		c.Forwards = append(c.Forwards, in)
	}
	for i, srv := range f.Service {
		out, err := resolveService(srv, i+1)
		if err != nil {
			return err
		}
		c.Services = append(c.Services, out)
	}
	return nil
}

// fillDefaults puts the built-in values into the blank fields of f. The link
// address is deliberately left alone: which end of the connection dials is the
// one thing Resolve needs to know whether the file actually said.
func fillDefaults(f File) File {
	if strings.TrimSpace(f.Network.Gateway) == "" {
		f.Network.Gateway = DefaultGateway
	}
	if strings.TrimSpace(f.Network.DNSIP) == "" {
		f.Network.DNSIP = DefaultDNS
	}
	if strings.TrimSpace(f.Network.GuestIP) == "" {
		f.Network.GuestIP = DefaultGuest
	}
	if strings.TrimSpace(f.Network.Netmask) == "" {
		f.Network.Netmask = DefaultNetmask
	}
	if strings.TrimSpace(f.Network.Domain) == "" {
		f.Network.Domain = DefaultDomain
	}
	if f.Network.MTU == 0 {
		f.Network.MTU = DefaultMTU
	}
	if strings.TrimSpace(f.DHCP.LeaseTime) == "" {
		f.DHCP.LeaseTime = DefaultLease.String()
	}
	if f.DHCP.PoolSize == 0 {
		f.DHCP.PoolSize = DefaultPoolSize
	}
	return f
}

func resolveForward(fwd Forward, n int, defaultGuest net.IP) (Inbound, error) {
	proto, err := parseProtocol(fwd.Proto)
	if err != nil {
		return Inbound{}, fmt.Errorf("forward %d: %v", n, err)
	}
	in := Inbound{Proto: proto, HostAddr: strings.TrimSpace(fwd.HostAddr)}
	if in.HostAddr == "" {
		in.HostAddr = "127.0.0.1"
	}
	if in.HostPort, err = checkPort(fwd.HostPort, fmt.Sprintf("forward %d.host_port", n)); err != nil {
		return Inbound{}, err
	}
	if in.GuestPort, err = checkPort(fwd.GuestPort, fmt.Sprintf("forward %d.guest_port", n)); err != nil {
		return Inbound{}, err
	}
	guest := strings.TrimSpace(fwd.GuestAddr)
	if guest == "" {
		guest = defaultGuest.String()
	}
	if in.GuestAddr, err = parseIP(fmt.Sprintf("forward %d.guest_addr", n), guest); err != nil {
		return Inbound{}, err
	}
	return in, nil
}

func resolveService(srv Service, n int) (Outbound, error) {
	proto, err := parseProtocol(srv.Proto)
	if err != nil {
		return Outbound{}, fmt.Errorf("service %d: %v", n, err)
	}
	out := Outbound{Proto: proto, HostAddr: strings.TrimSpace(srv.HostAddr)}
	if out.HostAddr == "" {
		out.HostAddr = "127.0.0.1"
	}
	if out.GuestPort, err = checkPort(srv.GuestPort, fmt.Sprintf("service %d.guest_port", n)); err != nil {
		return Outbound{}, err
	}
	if out.HostPort, err = checkPort(srv.HostPort, fmt.Sprintf("service %d.host_port", n)); err != nil {
		return Outbound{}, err
	}
	// Names are resolved here so the engine never has to look anything up
	// while it is serving the guest.
	if net.ParseIP(out.HostAddr) == nil {
		addrs, aerr := net.LookupHost(out.HostAddr)
		if aerr != nil || len(addrs) == 0 {
			return Outbound{}, fmt.Errorf("service %d.host_addr %q cannot be resolved", n, out.HostAddr)
		}
		out.HostAddr = addrs[0]
	}
	return out, nil
}

// checkResolver accepts a resolver as an address or an address with a port;
// everything else would fail later, inside a query, where it is much harder to
// see.
func checkResolver(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return errors.New("dns: upstreams has an empty entry")
	}
	host := entry
	if h, port, err := net.SplitHostPort(entry); err == nil {
		host = h
		if _, err := strconv.Atoi(port); err != nil {
			return fmt.Errorf("dns: upstream %q has no numeric port", entry)
		}
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("dns: upstream %q is not an IP address (the gateway has no resolver of its own to ask)", entry)
	}
	return nil
}
