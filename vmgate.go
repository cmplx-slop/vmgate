// Package vmgate runs the gateway as a library, in the caller's process.
//
// The whole public surface is Serve and Config: the caller brings an
// already-connected stream to QEMU's -netdev stream (a socketpair whose other
// end was passed to QEMU with addr.type=fd is the intended shape), and the
// gateway pumps ethernet frames through it until the session ends or ctx is
// cancelled. Everything behind this package stays in internal/.
//
//	cmd.ExtraFiles = []*os.File{childEnd} // QEMU: addr.type=fd,addr.str=3
//	go vmgate.Serve(ctx, parentConn, cfg, log)
package vmgate

import (
	"context"
	"errors"
	"net"
	"path/filepath"

	"log/slog"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/engine"
)

// Config is the gateway configuration a caller can set. It is a flat struct of
// plain types on purpose: it carries only what a host application varies per
// guest, and every zero value means "use vmgate's built-in default" (the same
// defaults a TOML file would get). Pointers distinguish "unset" from "off" for
// the switches that default to on.
type Config struct {
	// VPNConf names the wg-quick configuration file whose tunnel carries the
	// guest's traffic. Required: the gateway never falls back to the host's
	// own connection. A relative path is resolved against the working
	// directory of the caller.
	VPNConf string

	// MTU is the ceiling for the link; 0 takes the built-in default (1500),
	// and the effective MTU is the smaller of this and the tunnel's.
	MTU int

	// Verbose: 0 errors, 1 info, 2 debug. nil takes the default.
	Verbose *int

	// Sniff logs every packet crossing the link. nil takes the default.
	Sniff *bool

	// AllowEgress and DenyEgress narrow what the guest may reach through the
	// tunnel; entries are addresses or CIDRs. nil leaves the built-in policy.
	AllowEgress []string
	DenyEgress  []string

	// DNSUpstreams are resolver addresses the gateway asks through the
	// tunnel; nil falls back to vpn.conf's DNS=, then the host's.
	DNSUpstreams []string
}

// Serve attaches the gateway to conn and runs one link session: it blocks
// until the guest disconnects, ctx is cancelled, or the gateway fails to
// start. The session's frames are ethernet frames in QEMU's stream framing,
// which is what -netdev stream,addr.type=fd puts on the wire.
//
// Cancelling ctx closes conn, which unblocks the session; Serve then returns
// the context's error. Closing conn from the other end (a guest powering off)
// ends the session normally. The engine is torn down before Serve returns, so
// no listener, route or goroutine outlives the call.
func Serve(ctx context.Context, conn net.Conn, cfg Config, log *slog.Logger) error {
	if conn == nil {
		return errors.New("vmgate: no link connection")
	}
	if cfg.VPNConf == "" {
		return errors.New("vmgate: Config.VPNConf is required (the guest has no egress without a tunnel)")
	}

	vpn, err := filepath.Abs(cfg.VPNConf)
	if err != nil {
		return err
	}

	f := config.DefaultFile()
	f.VPN.Conf = vpn
	if cfg.MTU != 0 {
		f.Network.MTU = uint(cfg.MTU)
	}
	if cfg.Verbose != nil {
		f.Log.Verbosity = *cfg.Verbose
	}
	if cfg.Sniff != nil {
		f.Log.Sniff = *cfg.Sniff
	}
	f.Gateway.AllowEgress = cfg.AllowEgress
	f.Gateway.DenyEgress = cfg.DenyEgress
	f.DNS.Upstreams = cfg.DNSUpstreams

	c, err := config.Resolve(f)
	if err != nil {
		return err
	}
	if log == nil {
		log = slog.Default()
	}

	eng, err := engine.New(c, log)
	if err != nil {
		return err
	}
	defer eng.Close()

	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks the session; Serve returns below
		case <-stopped:
		}
	}()

	err = eng.Serve(conn)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
