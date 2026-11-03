package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// full is a configuration that sets every setting, which is what the tests use
// as a base so that each case only has to change one thing.
const full = `
[link]
listen  = "unix:/tmp/full.sock"

[network]
gateway   = "10.0.2.2"
dns_ip    = "10.0.2.3"
guest_ip  = "10.0.2.15"
netmask   = "255.255.255.0"
mtu       = 1450
domain    = "test"
mac       = "52:54:00:aa:bb:cc"
guest_mac = "52:54:00:11:22:33"

[dhcp]
enabled    = true
lease_time = "2h"
pool_size  = 4

[gateway]
internet   = true

[dns]
upstreams = ["1.1.1.1", "8.8.8.8:5353"]
map_hosts = ["Host.Local."]

[[forward]]
host_addr  = "0.0.0.0"
host_port  = 2222
guest_addr = "10.0.2.15"
guest_port = 22

[[forward]]
host_port  = 2053
guest_port = 53
proto      = "udp"

[[service]]
guest_port = 80
host_addr  = "127.0.0.1"
host_port  = 8080

[[service]]
guest_port = 5353
host_addr  = "1.1.1.1"
host_port  = 53
proto      = "udp"

[log]
verbosity = 2
sniff     = true
`

// writeTOML puts text in a file and returns its path. A configuration without a
// tunnel is refused by design, so unless the test's own text names one this also
// writes a vpn.conf beside the file and appends the section that points at it by
// a relative path, which is how a path written in a configuration file is meant
// to be read.
func writeTOML(t *testing.T, text string) string {
	t.Helper()

	dir := t.TempDir()
	if !strings.Contains(text, "[vpn]") {
		if err := os.WriteFile(filepath.Join(dir, "vpn.conf"), []byte(sampleVPN), 0o600); err != nil {
			t.Fatalf("write vpn.conf: %v", err)
		}
		text += "\n[vpn]\nconf = \"vpn.conf\"\n"
	}

	path := filepath.Join(dir, "vmgate.toml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// sampleVPN is the smallest wg-quick file that reads as a real one. The config
// package only checks that the file exists and hands the path on; reading the
// tunnel itself is the vpn package's job, and its parsing is tested in wgconf.
const sampleVPN = `
[Interface]
PrivateKey = AK1rUu0k0o1HvpAf1BhFt3x3z3VJDncEgGnJq1DlYUw=
Address    = 10.76.0.1/32
DNS        = 10.76.0.2

[Peer]
PublicKey  = q6k9hP1r0k3Hw3q5Ff4b0l1P7Q2s5t8u9v0w1x2y3z4=
Endpoint   = 203.0.113.9:51820
AllowedIPs = 0.0.0.0/0
`

// vpnFile points a hand built file at a vpn.conf in the test's directory, for
// the cases that resolve a File rather than read one.
func vpnFile(t *testing.T, f File) File {
	t.Helper()

	path := filepath.Join(t.TempDir(), "vpn.conf")
	if err := os.WriteFile(path, []byte(sampleVPN), 0o600); err != nil {
		t.Fatalf("write vpn.conf: %v", err)
	}
	f.VPN.Conf = path
	return f
}

// defaults resolves the file defaults the way the tool would have to build them,
// which is to say with a tunnel named: there is no default gateway without one.
func defaults(t *testing.T) Config {
	t.Helper()

	cfg, err := Resolve(vpnFile(t, DefaultFile()))
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	return cfg
}

// loadTOML reads text as a configuration file.
func loadTOML(t *testing.T, text string, ov Overrides) Config {
	t.Helper()

	cfg, err := Load(writeTOML(t, text), ov)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

// mustReject checks that a file is refused, and says which one.
func mustReject(t *testing.T, text string) {
	t.Helper()

	if _, err := Load(writeTOML(t, text), Overrides{}); err == nil {
		t.Fatalf("accepted:\n%s", text)
	}
}

func TestDefaults(t *testing.T) {
	cfg := defaults(t)

	if got := cfg.GatewayIP.String(); got != DefaultGateway {
		t.Fatalf("gateway = %s, want %s", got, DefaultGateway)
	}
	if got := cfg.DNSIP.String(); got != DefaultDNS {
		t.Fatalf("dns_ip = %s, want %s", got, DefaultDNS)
	}
	if got := cfg.GuestIP.String(); got != DefaultGuest {
		t.Fatalf("guest_ip = %s, want %s", got, DefaultGuest)
	}
	if ones, bits := cfg.Mask.Size(); ones != 24 || bits != 32 {
		t.Fatalf("netmask = %v, want /24", cfg.Mask)
	}
	if cfg.MTU != DefaultMTU {
		t.Fatalf("mtu = %d, want %d", cfg.MTU, DefaultMTU)
	}
	if !cfg.DHCP || !cfg.Internet {
		t.Fatal("DHCP and internet translation are on by default")
	}
	if cfg.LeaseTime != DefaultLease {
		t.Fatalf("lease_time = %v", cfg.LeaseTime)
	}
	if cfg.PoolSize != DefaultPoolSize {
		t.Fatalf("pool_size = %d, want %d", cfg.PoolSize, DefaultPoolSize)
	}
	if cfg.Verbose != DefaultVerbosity {
		t.Fatalf("verbosity = %d, want %d", cfg.Verbose, DefaultVerbosity)
	}
	// With nothing saying which end dials, the gateway waits for QEMU on a
	// private socket named after the guest.
	if !strings.HasPrefix(cfg.Listen, "unix:") || filepath.Base(cfg.Listen) != "vmgate-"+DefaultGuest+".sock" {
		t.Fatalf("listen = %q, want a unix socket named vmgate-%s.sock", cfg.Listen, DefaultGuest)
	}
	if cfg.Connect != "" {
		t.Fatalf("connect = %q, want nothing", cfg.Connect)
	}
	if want := "52:54:00:00:02:02"; cfg.MAC.String() != want {
		t.Fatalf("derived mac = %s, want %s", cfg.MAC, want)
	}
	if cfg.GuestMAC != nil {
		t.Errorf("guest_mac = %s, want unset", cfg.GuestMAC)
	}
}

// An empty file must resolve to exactly the defaults.
func TestEmptyFileIsDefaults(t *testing.T) {
	got := defaults(t)
	fromFile := loadTOML(t, "\n", Overrides{})
	if fromFile.MTU != got.MTU || fromFile.Listen != got.Listen || !fromFile.DHCP || !fromFile.Internet {
		t.Fatalf("empty file gave %+v, want the defaults", fromFile)
	}
}

func TestFullFile(t *testing.T) {
	cfg := loadTOML(t, full, Overrides{})

	if cfg.Listen != "unix:/tmp/full.sock" || cfg.Connect != "" {
		t.Errorf("link = %q / %q", cfg.Listen, cfg.Connect)
	}
	if cfg.MTU != 1450 || cfg.Domain != "test" {
		t.Errorf("mtu/domain = %d/%s", cfg.MTU, cfg.Domain)
	}
	if cfg.MAC.String() != "52:54:00:aa:bb:cc" {
		t.Errorf("mac = %s", cfg.MAC)
	}
	if cfg.GuestMAC.String() != "52:54:00:11:22:33" {
		t.Errorf("guest_mac = %s", cfg.GuestMAC)
	}
	if cfg.LeaseTime != 2*time.Hour || cfg.PoolSize != 4 {
		t.Errorf("dhcp = %v, pool %d", cfg.LeaseTime, cfg.PoolSize)
	}
	if want := []string{"1.1.1.1", "8.8.8.8:5353"}; len(cfg.DNS) != 2 || cfg.DNS[0] != want[0] || cfg.DNS[1] != want[1] {
		t.Errorf("dns upstreams = %v, want %v", cfg.DNS, want)
	}
	ip, ok := cfg.ExtraHosts["host.local"]
	if !ok || !ip.Equal(cfg.GatewayIP) {
		t.Errorf("map_hosts gave %v, want host.local -> the gateway", cfg.ExtraHosts)
	}
	if cfg.Verbose != 2 || !cfg.SniffPackets {
		t.Errorf("log = %d sniff %v", cfg.Verbose, cfg.SniffPackets)
	}

	if len(cfg.Forwards) != 2 {
		t.Fatalf("forwards = %d, want 2", len(cfg.Forwards))
	}
	first := cfg.Forwards[0]
	if first.HostAddr != "0.0.0.0" || first.HostPort != 2222 {
		t.Errorf("forward 1 host side = %s:%d", first.HostAddr, first.HostPort)
	}
	if first.GuestAddr.String() != "10.0.2.15" || first.GuestPort != 22 || first.Proto != TCP {
		t.Errorf("forward 1 guest side = %s:%d/%s", first.GuestAddr, first.GuestPort, first.Proto)
	}
	second := cfg.Forwards[1]
	if second.HostAddr != "127.0.0.1" {
		t.Errorf("forward 2 host_addr default = %s, want 127.0.0.1", second.HostAddr)
	}
	if !second.GuestAddr.Equal(cfg.GuestIP) {
		t.Errorf("forward 2 guest_addr default = %s, want the guest %s", second.GuestAddr, cfg.GuestIP)
	}
	if second.Proto != UDP {
		t.Errorf("forward 2 proto = %s, want udp", second.Proto)
	}

	if len(cfg.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(cfg.Services))
	}
	srv := cfg.Services[0]
	if srv.GuestPort != 80 || srv.HostAddr != "127.0.0.1" || srv.HostPort != 8080 {
		t.Errorf("service = %+v, want gateway:80 -> 127.0.0.1:8080", srv)
	}
	if cfg.Services[1].Proto != UDP || cfg.Services[1].HostAddr != "1.1.1.1" {
		t.Errorf("service 2 = %+v", cfg.Services[1])
	}

	// The tunnel: named by a relative path in the file, and handed on absolute.
	if !filepath.IsAbs(cfg.VPN) || filepath.Base(cfg.VPN) != "vpn.conf" {
		t.Errorf("vpn.conf = %q, want the absolute path of a vpn.conf beside the file", cfg.VPN)
	}
}

func TestOverrides(t *testing.T) {
	// A file that listens, a command line that dials: the mode flips, it does
	// not become a conflict.
	cfg := loadTOML(t, full, Overrides{Connect: "tcp:127.0.0.1:12340"})
	if cfg.Connect != "tcp:127.0.0.1:12340" || cfg.Listen != "" {
		t.Errorf("link = %q / %q, want the connect override alone", cfg.Listen, cfg.Connect)
	}

	verbose := 0
	sniff := false
	cfg = loadTOML(t, full, Overrides{Listen: "unix:/tmp/other.sock", Verbose: &verbose, Sniff: &sniff})
	if cfg.Listen != "unix:/tmp/other.sock" || cfg.Connect != "" {
		t.Errorf("listen override = %q", cfg.Listen)
	}
	if cfg.Verbose != 0 || cfg.SniffPackets {
		t.Errorf("log overrides = %d sniff %v, want 0 false", cfg.Verbose, cfg.SniffPackets)
	}

	// The verbosity the file asks for survives when the flag was not given.
	cfg = loadTOML(t, full, Overrides{})
	if cfg.Verbose != 2 {
		t.Errorf("verbosity = %d, want the file's 2", cfg.Verbose)
	}
}
