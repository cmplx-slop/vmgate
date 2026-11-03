package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// parseKey reads one of wg's base64 keys. The value is never repeated in an
// error: this is the key line of a VPN file, and echoing it would put a private
// key into the startup error, the journal and every bug report that follows.
func parseKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("is not base64 (%v)", err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("is %d bytes, want 32", len(k))
	}
	return k, nil
}

// parsePrefix reads an address or a prefix as it was written. The host bits are
// kept: for an interface address they are the address.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		// wg-quick accepts a bare address and means a host route.
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an address or a prefix", s)
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a prefix: %v", s, err)
	}
	if !p.Addr().Is4() && !p.Addr().Is6() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP prefix", s)
	}
	return p, nil
}

// parseRoute reads one AllowedIPs entry, where a prefix is a network and the
// host bits are noise: wg-quick is full of files that say 10.0.0.0/24 and mean
// the network.
func parseRoute(s string) (netip.Prefix, error) {
	p, err := parsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// stripComment removes a trailing comment.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' || line[i] == ';' {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

func hexOf(k []byte) string { return hex.EncodeToString(k) }

func isZero(k []byte) bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
