package main

import (
	"context"
	"log/slog"
	"time"

	"vmgate/internal/engine"
	"vmgate/internal/vpn"
)

// statsLoop reports what the gateway is doing, so a running instance is
// observable without any control socket.
func statsLoop(ctx context.Context, eng *engine.Engine, log *slog.Logger) {
	// Whether the peer has ever answered is the first thing to know about a
	// tunnel, and wg takes a couple of seconds at most to find out, so ask
	// once early instead of waiting for the first stats interval.
	early := time.NewTimer(5 * time.Second)
	defer early.Stop()

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-early.C:
			warnTunnel(eng.Stats(), log)
		case <-t.C:
			s := eng.Stats()
			log.Info("stats",
				"rx_frames", s.Link.RxFrames,
				"rx_bytes", s.Link.RxBytes,
				"tx_frames", s.Link.TxFrames,
				"tx_bytes", s.Link.TxBytes,
				"dropped", s.Link.Dropped,
				"link_held", s.Link.Held,
				"relays", s.Relays,
				"conns", s.Conns,
				"paths", s.Paths,
				"denied", s.Denied,
				"icmp_answered", s.EchoAnswered,
				"icmp_relayed", s.EchoRelayed,
				"leases", len(s.Leases),
				"forward_conns", s.HostBridges,
				"forward_refused", s.HostRefused,
				"vpn_endpoint", s.VPN.Endpoint,
				"vpn_handshake", handshakeAge(s.VPN),
				"vpn_tx", s.VPN.Tx,
				"vpn_rx", s.VPN.Rx,
				"vpn_refused", s.VPN.Dropped,
				"vpn_misaimed", s.VPN.Misaimed,
				"vpn_oversize", s.VPN.Oversize,
			)
			warnTunnel(s, log)
		}
	}
}

// warnTunnel says out loud what an empty tunnel means: the commonest reason a
// guest reaches nothing at all is a peer that has never answered, because of a
// wrong key or a UDP port that never arrives.
func warnTunnel(s engine.Stats, log *slog.Logger) {
	if !s.VPN.Handshake.IsZero() {
		return
	}
	log.Warn("the tunnel has never completed a handshake",
		"endpoint", s.VPN.Endpoint,
		"why", "the guest cannot reach anything beyond the gateway until the peer answers")
}

// handshakeAge is how long ago the VPN peer last answered, or "never" when it
// has not answered since the gateway started.
func handshakeAge(p vpn.PeerState) string {
	if p.Handshake.IsZero() {
		return "never"
	}
	return time.Since(p.Handshake).Round(time.Second).String()
}
