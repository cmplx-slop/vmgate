package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The settings the command line no longer has: a wrong value has to be caught
// by the loader, because there is nobody to notice a typo later.
func TestRejectsBadValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"both link ends", "[link]\nlisten = \"unix:/tmp/a\"\nconnect = \"unix:/tmp/b\"\n"},
		{"bad gateway", "[network]\ngateway = \"10.0.2\"\n"},
		{"bad dns ip", "[network]\ndns_ip = \"nope\"\n"},
		{"bad guest ip", "[network]\nguest_ip = \"nope\"\n"},
		{"bad netmask", "[network]\nnetmask = \"wide\"\n"},
		{"mtu huge", "[network]\nmtu = 70000\n"},
		{"bad mac", "[network]\nmac = \"not-a-mac\"\n"},
		{"bad guest mac", "[network]\nguest_mac = \"not-a-mac\"\n"},
		{"bad lease time", "[dhcp]\nlease_time = \"yesterday\"\n"},
		{"lease too short", "[dhcp]\nlease_time = \"5s\"\n"},
		{"pool negative", "[dhcp]\npool_size = -1\n"},
		{"pool huge", "[dhcp]\npool_size = 100000\n"},
		{"forward no host port", "[[forward]]\nguest_port = 22\n"},
		{"forward no guest port", "[[forward]]\nhost_port = 2222\n"},
		{"forward bad proto", "[[forward]]\nhost_port = 2222\nguest_port = 22\nproto = \"sctp\"\n"},
		{"forward bad guest addr", "[[forward]]\nhost_port = 2222\nguest_port = 22\nguest_addr = \"nope\"\n"},
		{"service no guest port", "[[service]]\nhost_port = 8080\n"},
		{"service no host port", "[[service]]\nguest_port = 80\n"},
		{"service bad proto", "[[service]]\nguest_port = 80\nhost_port = 8080\nproto = \"icmp\"\n"},
		{"service unresolvable host", "[[service]]\nguest_port = 80\nhost_addr = \"no.such.host.invalid\"\nhost_port = 8080\n"},
		{"dns by name", "[dns]\nupstreams = [\"resolver.example.com\"]\n"},
		{"dns bad port", "[dns]\nupstreams = [\"1.1.1.1:domain\"]\n"},
		{"dns empty entry", "[dns]\nupstreams = [\"\"]\n"},
		{"empty map host", "[dns]\nmap_hosts = [\"  .\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mustReject(t, tc.text)
		})
	}
}

func TestRejectsMalformedFile(t *testing.T) {
	path := writeTOML(t, "[network]\ngateway = ")
	if _, err := Load(path, Overrides{}); err == nil {
		t.Fatal("a truncated assignment was accepted")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name the file", err)
	}

	// A setting that does not exist is a typo, and a typo in a file would
	// otherwise never be noticed.
	_, err := Load(writeTOML(t, "[network]\ngetway = \"10.0.2.2\"\n"), Overrides{})
	if err == nil {
		t.Fatal("an unknown setting was accepted")
	}
	if !strings.Contains(err.Error(), "network.getway") {
		t.Errorf("error %q does not name the unknown setting", err)
	}

	// link.framing chose between two ways of delimiting frames. There is one
	// way now, so a file that still sets it is refused by name instead of being
	// quietly ignored: the operator has to know the switch is gone.
	_, err = Load(writeTOML(t, "[link]\nframing = \"len32\"\n"), Overrides{})
	if err == nil {
		t.Fatal("the retired link.framing was accepted")
	}
	if !strings.Contains(err.Error(), "link.framing") {
		t.Errorf("error %q does not name the retired setting", err)
	}

	// Same for gateway.map_ports, which was a way for the guest to reach the
	// host's own ports: the setting is gone, and a file that still turns it on
	// has to be told so rather than run without it.
	_, err = Load(writeTOML(t, "[gateway]\nmap_ports = true\n"), Overrides{})
	if err == nil {
		t.Fatal("the retired gateway.map_ports was accepted")
	}
	if !strings.Contains(err.Error(), "gateway.map_ports") {
		t.Errorf("error %q does not name the retired setting", err)
	}

	// A port that does not fit in 16 bits is refused by the decoder.
	mustReject(t, "[[forward]]\nhost_port = 70000\nguest_port = 22\n")

	// And a file that is not there is an error, not a run on defaults.
	if _, err := Load(filepath.Join(t.TempDir(), "missing.toml"), Overrides{}); err == nil {
		t.Error("a missing configuration file was accepted")
	}
	if _, err := Load("", Overrides{}); err == nil {
		t.Error("no configuration file at all was accepted")
	}
}

// Without a tunnel there is no way out for a guest, so the configuration is
// refused at startup rather than quietly reaching for the host's own connection.
func TestTunnelIsRequired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vmgate.toml")
	text := "[network]\ngateway = \"10.0.2.2\"\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := Load(path, Overrides{})
	if err == nil {
		t.Fatal("a configuration with no vpn.conf was accepted")
	}
	if !strings.Contains(err.Error(), "vpn") {
		t.Errorf("error = %v: it has to say that the tunnel is what is missing", err)
	}
}

// A tunnel file that is named but not there is a typo, and a typo about a
// tunnel is worth stopping for.
func TestTunnelFileMustExist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vmgate.toml")
	text := "[vpn]\nconf = " + quote(filepath.Join(dir, "absent.conf")) + "\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Load(path, Overrides{}); err == nil {
		t.Fatal("a vpn.conf that does not exist was accepted")
	}
}

// A path written in the file sits next to the file, so a guest definition can be
// moved between machines without rewriting it.
func TestTunnelPathIsRelativeToTheFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "tunnel"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tunnel", "vpn.conf"), []byte(sampleVPN), 0o600); err != nil {
		t.Fatalf("write vpn.conf: %v", err)
	}

	path := filepath.Join(dir, "vmgate.toml")
	text := "[vpn]\nconf = " + quote("tunnel/vpn.conf") + "\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path, Overrides{})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if want := filepath.Join(dir, "tunnel", "vpn.conf"); cfg.VPN != want {
		t.Fatalf("vpn.conf = %q, want %q", cfg.VPN, want)
	}
}

// The command line may name a different tunnel for the same guest, and a path
// given there is the shell's, not the file's.
func TestTunnelOverride(t *testing.T) {
	dir := t.TempDir()
	vpn := filepath.Join(dir, "other.conf")
	if err := os.WriteFile(vpn, []byte(sampleVPN), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	path := filepath.Join(dir, "vmgate.toml")
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path, Overrides{VPN: vpn})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.VPN != vpn {
		t.Fatalf("vpn.conf = %q, want the override %q", cfg.VPN, vpn)
	}

	rel := "other.conf"
	if err := os.WriteFile(filepath.Join(dir, rel), []byte(sampleVPN), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The same path is not there relative to the working directory, so if the
	// override were resolved against the file it would be found and this would
	// pass for the wrong reason.
	if _, err := Load(path, Overrides{VPN: rel}); err == nil {
		t.Fatal("a relative -vpn was resolved against the configuration file")
	}
}

// A key that does not exist in the vpn section is refused like everywhere else:
// a setting that is silently ignored in a file about a tunnel is a hole waiting
// to happen.
func TestTunnelRejectsUnknownKey(t *testing.T) {
	mustReject(t, "[vpn]\nconf = \"vpn.conf\"\nroute_all = true\n")
}
