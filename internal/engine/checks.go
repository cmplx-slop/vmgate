package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"

	"vmgate/internal/wgconf"
)

// warnIfShared says what the file's own permissions say about the tunnel's
// private key. The gateway only reads the file, once, and never writes it, so
// the one thing left to do is point out that anyone on this machine can read
// the key out of it.
func warnIfShared(path string, log *slog.Logger) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	perm := st.Mode().Perm()
	if perm&0o077 == 0 {
		return
	}
	log.Warn("vpn: the tunnel file is readable by others",
		"path", path, "mode", perm.String(),
		"why", "it holds the tunnel's private key: chmod 600 it")
}

// checkTunnel refuses the tunnel settings that would put the tunnel and the
// guest's link in each other's way. Both mistakes are easy to make with a
// borrowed vpn.conf, and neither shows up as anything but traffic going
// somewhere surprising.
//
// Every address is checked, not just the first: the tunnel installs all of them
// on its NIC, and one address inside the guest's subnet is enough to let the
// peer answer for a machine on the guest's own segment.
func (e *Engine) checkTunnel(conf *wgconf.Config) error {
	ones, _ := e.cfg.Mask.Size()
	tunnelIPs := 0
	seen := map[string]bool{}

	for _, pre := range conf.Addresses {
		if !pre.Addr().Is4() {
			continue
		}
		ip := net.IP(pre.Addr().AsSlice())
		if seen[ip.String()] {
			return fmt.Errorf("vpn: the tunnel configuration names address %s more than once", ip)
		}
		seen[ip.String()] = true
		tunnelIPs++

		if e.cfg.Subnet().Contains(ip) {
			return fmt.Errorf("vpn: the tunnel address %s is inside the guest's subnet %s/%d, so the tunnel and the QEMU link would be the same network",
				ip, e.cfg.GatewayIP, ones)
		}
	}
	if tunnelIPs == 0 {
		return errors.New("vpn: the tunnel configuration has no IPv4 address")
	}

	// An AllowedIPs entry covering the guest's own subnet is not fatal: that
	// subnet has its own route, and a guest is never allowed a relay for an
	// address on its own segment (see svc.Manager.Inspect). It is worth one
	// line, because it is the kind of thing that costs an evening to find.
	if v4 := e.cfg.GatewayIP.To4(); v4 != nil {
		gw, ok := netip.AddrFromSlice(v4)
		if ok {
			for _, pre := range conf.V4Routes() {
				if pre.Contains(gw) {
					e.log.Warn("vpn: an AllowedIPs entry covers the guest's subnet",
						"allowed", pre.String(), "gateway", e.cfg.GatewayIP,
						"note", "the subnet keeps its own route to the QEMU link, and a guest is refused a destination inside it")
					break
				}
			}
		}
	}
	return nil
}
