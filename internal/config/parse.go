package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// defaultSocketPath picks where to wait for QEMU when the file did not say. A
// socket in a shared directory is one any other user can attach to as the
// guest, or block simply by taking the name first, so the per-user runtime
// directory is used when the system publishes one, and a directory of our own
// otherwise.
func defaultSocketPath(guestIP string) string {
	if dir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); filepath.IsAbs(dir) {
		return filepath.Join(dir, "vmgate-"+guestIP+".sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("vmgate-%d", os.Geteuid()), "vmgate-"+guestIP+".sock")
}

// deriveMAC builds a stable, locally administered MAC for an IPv4 address,
// in the spirit of QEMU's 52:54:00 prefix.
func deriveMAC(ip net.IP) net.HardwareAddr {
	v4 := ip.To4()
	if v4 == nil {
		v4 = []byte{0, 0, 0, 0}
	}
	return net.HardwareAddr{0x52, 0x54, 0x00, v4[1], v4[2], v4[3]}
}

func parseIP(field, s string) (net.IP, error) {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return nil, fmt.Errorf("%s: %q is not an IP address", field, s)
	}
	return ip, nil
}

func parseMAC(field, s string) (net.HardwareAddr, error) {
	mac, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", field, err)
	}
	return mac, nil
}

func parseMask(field, s string) (net.IPMask, error) {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
		return net.IPMask(ip.To4()), nil
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.Mask, nil
	}
	ones, err := strconv.Atoi(s)
	if err == nil && ones >= 0 && ones <= 32 {
		return net.CIDRMask(ones, 32), nil
	}
	return nil, fmt.Errorf("%s: %q is not a netmask", field, s)
}

func parseDuration(field, s string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration (try \"24h\")", field, s)
	}
	return d, nil
}

func checkPort(p uint16, field string) (uint16, error) {
	if p == 0 {
		return 0, fmt.Errorf("%s: port is required and must be 1-65535", field)
	}
	return p, nil
}
