package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNetmaskForms(t *testing.T) {
	for _, tc := range []struct {
		value string
		ones  int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"24", 24},
		{"10.0.2.0/16", 16},
	} {
		cfg := loadTOML(t, "[network]\nnetmask = "+quote(tc.value), Overrides{})
		if ones, _ := cfg.Mask.Size(); ones != tc.ones {
			t.Errorf("netmask %q gave /%d, want /%d", tc.value, ones, tc.ones)
		}
	}
}

// A 0 is what an omitted number decodes to, so it means the default rather
// than an out of range value; only the values out of range are refused.
func TestZeroMeansDefault(t *testing.T) {
	cfg := loadTOML(t, "[network]\nmtu = 0\n[dhcp]\npool_size = 0\nlease_time = \"\"\n", Overrides{})
	if cfg.MTU != DefaultMTU {
		t.Errorf("mtu = %d, want the default %d", cfg.MTU, DefaultMTU)
	}
	if cfg.PoolSize != DefaultPoolSize {
		t.Errorf("pool_size = %d, want the default %d", cfg.PoolSize, DefaultPoolSize)
	}
	if cfg.LeaseTime != DefaultLease {
		t.Errorf("lease_time = %v, want the default %v", cfg.LeaseTime, DefaultLease)
	}
}

func TestDeriveMAC(t *testing.T) {
	cases := map[string]string{
		"10.0.2.2":    "52:54:00:00:02:02",
		"192.168.9.1": "52:54:00:a8:09:01",
	}
	for ip, want := range cases {
		got := deriveMAC(net.ParseIP(ip)).String()
		if got != want {
			t.Fatalf("deriveMAC(%s) = %s, want %s", ip, got, want)
		}
	}
	// Locally administered and unicast: the second least significant bit of
	// the first octet must be set, the multicast bit clear.
	mac := deriveMAC(net.ParseIP("10.0.2.2"))
	if mac[0]&0x03 != 0x02 {
		t.Fatalf("mac %s is not locally administered", mac)
	}
}

// A hand built file, as the test fixture builds one, has to be as usable as a
// file read from disk.
func TestHandBuiltFile(t *testing.T) {
	f := vpnFile(t, DefaultFile())
	f.Network.Gateway = "192.168.9.2"
	f.Service = []Service{{GuestPort: 80, HostPort: 8080}}

	cfg, err := Resolve(f)
	if err != nil {
		t.Fatal(err)
	}
	if want := "52:54:00:a8:09:02"; cfg.MAC.String() != want {
		t.Errorf("mac = %s, want it derived from the gateway as %s", cfg.MAC, want)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].HostAddr != "127.0.0.1" {
		t.Errorf("services = %v", cfg.Services)
	}
	if cfg.LeaseTime != DefaultLease || cfg.PoolSize != DefaultPoolSize {
		t.Errorf("dhcp = %v pool %d, want the defaults", cfg.LeaseTime, cfg.PoolSize)
	}
}

// The default socket is the one thing the program chooses for itself, and a
// guessable path in a shared directory is a hole: another user can attach as
// the guest, or take the name first and stop the gateway from starting.
func TestDefaultSocketIsPrivate(t *testing.T) {
	base := t.TempDir()
	t.Setenv("TMPDIR", base)

	t.Setenv("XDG_RUNTIME_DIR", "")
	cfg := defaults(t)
	if want := "unix:" + filepath.Join(base, fmt.Sprintf("vmgate-%d", os.Geteuid()), "vmgate-"+DefaultGuest+".sock"); cfg.Listen != want {
		t.Errorf("listen = %q, want a per-user directory under $TMPDIR: %q", cfg.Listen, want)
	}

	t.Setenv("XDG_RUNTIME_DIR", base+"/runtime")
	cfg = defaults(t)
	if want := "unix:" + filepath.Join(base+"/runtime", "vmgate-"+DefaultGuest+".sock"); cfg.Listen != want {
		t.Errorf("listen = %q, want the runtime directory: %q", cfg.Listen, want)
	}
}

// Where the socket path came from is recorded, because it decides how strictly
// its directory is treated.
func TestLinkDefaultIsMarked(t *testing.T) {
	cfg := defaults(t)
	if !cfg.LinkDefault {
		t.Error("the socket path we invented was not marked as ours")
	}

	cfg = loadTOML(t, "[link]\nlisten = "+quote("/tmp/gw.sock")+"\n", Overrides{})
	if cfg.LinkDefault {
		t.Error("a socket the operator named was marked as ours")
	}

	cfg = loadTOML(t, "", Overrides{Connect: "tcp:127.0.0.1:12340"})
	if cfg.LinkDefault {
		t.Error("connect mode should not claim a default socket")
	}
}
