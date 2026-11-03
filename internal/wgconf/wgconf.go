package wgconf

import (
	"fmt"
	"os"
)

// Package wgconf reads a WireGuard configuration in the wg-quick .conf format,
// the file `wg-quick up` would take.
//
// vmgate does not use wg-quick, wg or any kernel interface: the file is read
// here, validated, and handed to wireguard-go as its own configuration. That
// means the same file an operator already has for a VPN keeps working here, with
// these limits, all of them found at startup rather than in the middle of a
// connection:
//
//   - IPv4 only. An [Interface] needs at least one IPv4 Address; IPv6 addresses
//     and AllowedIPs are accepted but ignored.
//   - Exactly one peer, which is what routing one VM's traffic through one VPN
//     needs. More than one [Peer] is an error rather than a surprise.
//   - DNS entries must be addresses: the gateway has no resolver of its own to
//     ask before the tunnel exists. A peer Endpoint may be a name, because
//     reaching it is what the tunnel is for, and it is resolved once, by the
//     host, at startup.
//   - Keys are the base64 ones wg prints. A private key is never logged.

// Load reads and validates one configuration file.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vpn: %v", err)
	}
	defer f.Close()

	return Parse(path, f)
}
