package vpn

import (
	"strconv"
	"strings"
	"time"

	"vmgate/internal/wgconf"
)

// shortKey is enough of a public key to tell two peers apart in a log line
// without spilling the whole of it. Only ever call it with a public key.
func shortKey(k []byte) string {
	s := wgconf.KeyString(k)
	if len(s) <= 12 {
		return s
	}
	return s[:8] + "…"
}

// orNone keeps an absent value from reading like a mistake in a log line.
func orNone(s string) string {
	if s == "" {
		return "(peer dials in)"
	}
	return s
}

// PeerState is what the tunnel reports about the other end: enough to tell an
// operator whether the VPN is actually working, and no key material.
type PeerState struct {
	// ListenPort is the UDP port the tunnel receives on.
	ListenPort int

	// Endpoint is where the tunnel sends, as configured or as the peer's
	// packets arrived.
	Endpoint string

	// Handshake is when the peer last answered. The zero time means never,
	// which is what a wrong key or a blocked UDP port looks like.
	Handshake time.Time

	// Rx and Tx count bytes through wireguard-go, Dropped counts packets the
	// peer sent that were not well-formed IPv4, Misaimed counts the well-formed
	// ones aimed at an address this tunnel does not carry, and Oversize counts
	// packets going the other way that were too large for it. They are counted
	// apart because one is the peer's doing, one is the peer's aim, and one is
	// ours.
	Rx       int64
	Tx       int64
	Dropped  uint64
	Misaimed uint64
	Oversize uint64
}

// Peer asks wireguard-go for the state of the tunnel.
//
// The raw answer from the configuration interface includes the private key, so
// it is parsed here and never returned; only the fields above leave this
// function.
func (t *Tunnel) Peer() PeerState {
	state := PeerState{
		Dropped:  t.shim.Dropped(),
		Misaimed: t.shim.Misaimed(),
		Oversize: t.shim.Oversize(),
	}

	out, err := t.dev.IpcGet()
	if err != nil {
		return state
	}
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "listen_port":
			state.ListenPort = atoi(val)
		case "endpoint":
			state.Endpoint = val
		case "last_handshake_time_sec":
			if sec := atoi(val); sec > 0 {
				nsec := atoi(field(out, "last_handshake_time_nsec"))
				state.Handshake = time.Unix(int64(sec), int64(nsec))
			}
		case "rx_bytes":
			state.Rx = atoi64(val)
		case "tx_bytes":
			state.Tx = atoi64(val)
		}
		// private_key, public_key and preshared_key are deliberately ignored.
	}
	return state
}

func field(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
