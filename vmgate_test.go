package vmgate

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A malformed pass in Config must be refused by configuration resolution,
// before any listener opens — the same validation the TOML sections get.
func TestServeValidatesPasses(t *testing.T) {
	vpn := filepath.Join(t.TempDir(), "vpn.conf")
	if err := os.WriteFile(vpn, []byte("[Interface]\nPrivateKey = aaa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, peer := net.Pipe()
	defer peer.Close()

	err := Serve(context.Background(), conn, Config{
		VPNConf:  vpn,
		Forwards: []Forward{{HostPort: 0, GuestPort: 22}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "forward 1.host_port") {
		t.Fatalf("bad forward not refused: %v", err)
	}

	err = Serve(context.Background(), conn, Config{
		VPNConf:  vpn,
		Services: []Service{{GuestPort: 80, HostAddr: "no.such.host.invalid", HostPort: 8080}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "service 1.host_addr") {
		t.Fatalf("bad service not refused: %v", err)
	}
}
