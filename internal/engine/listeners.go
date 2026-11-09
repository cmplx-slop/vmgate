package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/cmplx-slop/vmgate/internal/config"
	"github.com/cmplx-slop/vmgate/internal/dhcp"
	"github.com/cmplx-slop/vmgate/internal/dns"
	"github.com/cmplx-slop/vmgate/internal/nsnet"
	"github.com/cmplx-slop/vmgate/internal/svc"
)

// startServices installs the [[service]] forwards and the DNS server.
func (e *Engine) startServices(dnsIPs []net.IP) error {
	for _, f := range e.cfg.Services {
		target := svc.Target{
			Addr: net.JoinHostPort(f.HostAddr, strconv.Itoa(int(f.HostPort))),
			Name: "service",
		}
		var err error
		switch f.Proto {
		case config.UDP:
			err = e.svcm.ServeUDP(e.cfg.GatewayIP, f.GuestPort, target)
		default:
			err = e.svcm.ServeTCP(e.cfg.GatewayIP, f.GuestPort, target)
		}
		if err != nil {
			return fmt.Errorf("service %s: %w", f, err)
		}
	}

	// DNS: synthetic names are answered here; everything else is relayed to a
	// resolver. The resolvers are the ones dns.upstreams names if it says any,
	// otherwise the ones in vpn.conf, otherwise the host's. Whichever they are,
	// the query goes through the tunnel: a guest's lookups leave the same way
	// its traffic does.
	resolvers, from, err := resolversFor(e.cfg.DNS, e.tunnel.DNS())
	if err != nil {
		return err
	}
	switch from {
	case hostResolvers:
		e.log.Warn("vpn.conf names no IPv4 DNS server, so the host's resolvers are asked through the tunnel",
			"servers", resolvers, "why", "a resolver the tunnel cannot reach means no lookups get answered")
	default:
		e.log.Debug("dns: upstream", "from", from, "servers", resolvers)
	}

	e.dnsSrv = dns.New(&dns.Failover{Servers: resolvers, Dial: e.tunnel.Resolver()}, e.log)
	for name, ip := range e.cfg.ExtraHosts {
		e.dnsSrv.AddHost(name, ip)
	}
	if err := e.dnsSrv.Register(e.svcm, 53, dnsIPs...); err != nil {
		return fmt.Errorf("dns: %w", err)
	}
	return nil
}

// startDHCP binds port 67 on the stack and serves leases.
func (e *Engine) startDHCP() error {
	if !e.cfg.DHCP {
		return nil
	}
	ep, err := nsnet.ListenUDP(e.stk, nicID, nil, 67)
	if err != nil {
		return fmt.Errorf("dhcp bind: %w", err)
	}
	e.dhcpEP = ep

	mask := e.cfg.Mask
	pool := dhcp.Pool{Start: e.cfg.GuestIP, Size: e.cfg.PoolSize}
	e.dhcpSrv = dhcp.NewServer(dhcp.ServerConfig{
		Gateway:   e.cfg.GatewayIP,
		DNS:       dnsList(e.cfg),
		Mask:      mask,
		Pool:      pool,
		LeaseTime: e.cfg.LeaseTime,
		Domain:    e.cfg.Domain,
		MTU:       uint32(e.cfg.MTU),
		PinMAC:    e.cfg.GuestMAC,
		Logger:    e.log,
	})

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.dhcpCancel = cancel
	e.mu.Unlock()

	go func() {
		// The DHCP server reads datagrams a guest wrote, so it is on the same
		// footing as the relays: one packet shape should not end the process.
		defer nsnet.Guard(e.log, "dhcp server")
		if err := e.dhcpSrv.Serve(ctx, dhcpConn{ep}); err != nil && !errors.Is(err, nsnet.ErrClosed) && ctx.Err() == nil {
			e.log.Error("dhcp server", "err", err)
		}
	}()
	e.log.Info("dhcp: serving", "pool", fmt.Sprintf("%s+%d", pool.Start, pool.Size), "gateway", e.cfg.GatewayIP, "dns", dnsList(e.cfg))
	return nil
}

// startForwards opens the host side listeners of the [[forward]] entries.
func (e *Engine) startForwards() error {
	e.forward = svc.NewForwarder(e.stk, nicID, e.log)
	e.forward.SetSourceIP(e.cfg.GatewayIP)
	for _, f := range e.cfg.Forwards {
		hostAddr := net.JoinHostPort(f.HostAddr, strconv.Itoa(int(f.HostPort)))
		guest := f.GuestAddr
		var err error
		switch f.Proto {
		case config.UDP:
			err = e.forward.ForwardUDP(hostAddr, guest, f.GuestPort)
		default:
			err = e.forward.ForwardTCP(hostAddr, guest, f.GuestPort)
		}
		if err != nil {
			return fmt.Errorf("forward %s: %w", f, err)
		}
	}
	return nil
}

// dhcpConn adapts a netstack UDP endpoint to the DHCP server's transport.
type dhcpConn struct{ u *nsnet.UDP }

func (c dhcpConn) Read(p []byte) (int, *net.UDPAddr, error) {
	n, from, err := c.u.Read(p)
	if errors.Is(err, nsnet.ErrClosed) {
		err = net.ErrClosed
	}
	return n, from, err
}

func (c dhcpConn) WriteTo(p []byte, to *net.UDPAddr) error {
	_, err := c.u.WriteTo(p, to)
	return err
}

func (c dhcpConn) Close() error { return c.u.Close() }
