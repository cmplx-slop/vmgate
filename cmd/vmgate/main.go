package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/engine"
)

// Command vmgate is a rootless userspace gateway between a QEMU guest and
// the host, in the spirit of passt and QEMU's user networking, but built on a
// gVisor netstack instead of a tap device.
//
// Everything the guest reaches beyond this machine goes through a WireGuard
// tunnel, run in this process by wireguard-go from an ordinary wg-quick
// configuration file. No kernel interface, no TUN device, no raw socket and no
// change to the host's routes: the only host socket in play is the tunnel's one
// UDP socket, plus the forwards the operator asks for.
//
// QEMU side. By default vmgate waits for QEMU to connect:
//
//	qemu-system-x86_64 ... \
//	  -netdev stream,id=n0,addr.type=unix,addr.path=/tmp/vmgate.sock \
//	  -device virtio-net-pci,netdev=n0
//
// With link.connect set, or -connect on the command line, it is the other way
// round: QEMU listens with server=on and vmgate dials in.
//
// vmgate side, with everything except the socket in a TOML file:
//
//	vmgate -config examples/vmgate.toml
//
// The configuration file is required, and so is the vpn.conf it names; see
// examples/vmgate.toml and examples/vpn.conf for annotated examples, and
// vmgate -h for the settings that can be overridden on the command line.

const name = "vmgate"

func main() {
	cfg, err := parseConfig(os.Args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		// The usage was printed; nothing went wrong.
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(2)
	}

	log := newLogger(cfg.Verbose)
	if err := run(cfg, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// parseConfig reads the configuration file named on the command line and
// applies the handful of settings that can still be overridden there.
func parseConfig(args []string) (config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var (
		path    = fs.String("config", "", "TOML configuration file (required)")
		listen  = fs.String("listen", "", "override link.listen: wait for QEMU (unix:PATH | tcp:HOST:PORT)")
		connect = fs.String("connect", "", "override link.connect: dial QEMU (unix:PATH | tcp:HOST:PORT)")
		vpn     = fs.String("vpn", "", "override vpn.conf: the WireGuard configuration the guest's traffic is routed through")
		verbose = fs.Int("v", config.DefaultVerbosity, "override log.verbosity: 0 errors, 1 info, 2 debug")
		sniff   = fs.Bool("sniff", false, "override log.sniff: log every packet crossing the link")
	)
	fs.Usage = func() { usage(fs) }

	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	if *path == "" {
		usage(fs)
		return config.Config{}, errors.New("-config is required")
	}

	// Only flags the user actually gave override the file: -v 0 and a file
	// that asks for verbosity 0 are different things.
	var ov config.Overrides
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "listen":
			ov.Listen = *listen
		case "connect":
			ov.Connect = *connect
		case "vpn":
			ov.VPN = *vpn
		case "v":
			ov.Verbose = verbose
		case "sniff":
			ov.Sniff = sniff
		}
	})

	cfg, err := config.Load(*path, ov)
	if err != nil {
		fmt.Fprintln(os.Stderr, "\nvmgate -h shows the file format")
		return cfg, err
	}
	return cfg, nil
}

// usage prints the flags and enough of the file format to get started; the
// annotated example carries the rest.
func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "usage: %s -config FILE [-listen ADDR | -connect ADDR] [-vpn FILE] [-v N] [-sniff]\n\n", name)
	fs.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Configuration is a TOML file. The shortest useful one:

	[link]
	listen = "unix:/tmp/vmgate.sock"

	[vpn]
	conf = "vpn.conf"         # required: the wg-quick file carrying the guest

	[[forward]]           # host ssh -> guest sshd
	host_port  = 2222
	guest_port = 22

	[[service]]           # guest gateway:80 -> host :8080
	guest_port = 80
	host_port  = 8080

The vpn.conf is the shape wg-quick takes: an [Interface] with PrivateKey,
Address and optionally DNS, ListenPort and MTU, and one [Peer] with PublicKey,
Endpoint and AllowedIPs. A guest reaches exactly those AllowedIPs; a destination
outside them has no route and is refused, never sent over the host's own
connection.

See examples/vmgate.toml and examples/vpn.conf for every setting.
`)
}

func newLogger(verbosity int) *slog.Logger {
	level := slog.LevelInfo
	switch {
	case verbosity <= 0:
		level = slog.LevelError
	case verbosity >= 2:
		level = slog.LevelDebug
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}

// run connects the gateway to QEMU and keeps it connected until interrupted.
func run(cfg config.Config, log *slog.Logger) error {
	eng, err := engine.New(cfg, log)
	if err != nil {
		return err
	}
	defer eng.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go statsLoop(ctx, eng, log)
	banner(cfg, log)

	if cfg.Listen != "" {
		return listenLoop(ctx, cfg, eng, log)
	}
	return dialLoop(ctx, cfg, eng, log)
}
