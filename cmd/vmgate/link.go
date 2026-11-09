package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/engine"
	"github.com/cmplx-slop/vmgate/internal/qemu"
)

// banner documents the QEMU invocation that matches this configuration, which
// saves anyone from digging through the manual at 2am.
func banner(cfg config.Config, log *slog.Logger) {
	if cfg.Listen == "" {
		log.Info("ready", "mode", "connect", "address", cfg.Connect,
			"qemu", fmt.Sprintf("-netdev stream,id=n0,server=on,addr.type=%s,...", networkKind(cfg.Connect)))
		return
	}
	addr := cfg.Listen
	log.Info("ready", "mode", "listen", "address", addr,
		"qemu", fmt.Sprintf("-netdev stream,id=n0,addr.type=%s,addr.path=%s -device virtio-net-pci,netdev=n0",
			networkKind(addr), pathPart(addr)))
}

func networkKind(addr string) string {
	a, err := qemu.ParseAddr(addr)
	if err != nil {
		return "unix"
	}
	if a.Network == "tcp" {
		return "inet"
	}
	return "unix"
}

func pathPart(addr string) string {
	a, err := qemu.ParseAddr(addr)
	if err != nil {
		return addr
	}
	return a.Name
}

// listenLoop waits for QEMU to dial us, serving one connection at a time.
func listenLoop(ctx context.Context, cfg config.Config, eng *engine.Engine, log *slog.Logger) error {
	addr, err := qemu.ParseAddr(cfg.Listen)
	if err != nil {
		return err
	}
	if !cfg.LinkDefault && addr.SharedDir() {
		// The socket is the guest's network: whoever can reach it is the
		// guest. Say so when the place the operator chose lets other users
		// reach it; a path we chose ourselves is checked rather than warned
		// about, just below.
		log.Warn("the link socket is in a directory other users can write to",
			"socket", addr.Name,
			"why", "another local process can take this name, or connect and become the guest",
			"fix", "point link.listen at a socket inside a private directory")
	}

	var l net.Listener
	if cfg.LinkDefault {
		l, err = addr.ListenPrivate()
	} else {
		l, err = addr.Listen()
	}
	if err != nil {
		return err
	}
	defer l.Close()

	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if qemu.IsStaleSocket(err) {
				return fmt.Errorf("listen %s: %w (is another vmgate running?)", addr, err)
			}
			log.Error("accept", "err", err)
			return err
		}
		if err := eng.Serve(conn); err != nil {
			log.Debug("link session ended", "err", err)
		}
	}
	log.Info("stopped listening", "address", cfg.Listen)
	return nil
}

// dialLoop keeps reconnecting to a QEMU that listens with server=on.
func dialLoop(ctx context.Context, cfg config.Config, eng *engine.Engine, log *slog.Logger) error {
	addr, err := qemu.ParseAddr(cfg.Connect)
	if err != nil {
		return err
	}
	backoff := 200 * time.Millisecond
	for ctx.Err() == nil {
		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := addr.Dial(dialCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Debug("connect", "address", addr, "err", err, "retry", backoff)
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
				if backoff < 5*time.Second {
					backoff *= 2
				}
			}
			continue
		}
		backoff = 200 * time.Millisecond
		if err := eng.Serve(conn); err != nil {
			log.Debug("link session ended", "err", err)
		}
	}
	return nil
}
