package engine

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"vmgate/internal/config"
	"vmgate/internal/ethlink"
	"vmgate/internal/nsnet"
	"vmgate/internal/svc"
	"vmgate/internal/vpn"
	"vmgate/internal/wgconf"
)

// lowerMTU takes the tunnel's MTU whenever it is the smaller of the two. A
// guest that sizes its packets for 1500 would have them fragmented on the way
// out; handing it the tunnel's number, on the link and over DHCP, keeps whole
// packets all the way through.
func (e *Engine) lowerMTU(conf *wgconf.Config) {
	mtu := uint32(e.cfg.MTU)
	if mtu == 0 {
		mtu = config.DefaultMTU
	}
	if uint32(conf.MTU) < mtu {
		e.log.Info("mtu: lowered to the tunnel's", "was", mtu, "now", conf.MTU)
		mtu = uint32(conf.MTU)
	}
	e.cfg.MTU = uint(mtu)
}

// buildStack creates the netstack, the link that faces QEMU and the addresses
// the gateway answers for itself. The second result names the addresses DNS
// may be served on.
func (e *Engine) buildStack() ([]net.IP, error) {
	cfg := e.cfg

	e.stk = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
		// HandleLocal must stay off. It means "a packet whose source address
		// is one of mine is for me", and with gateway.internet the NIC is promiscuous,
		// so every address the guest uses counts as one of ours: with
		// HandleLocal on, the stack throws away all of the guest's traffic as
		// "packets from myself".
		HandleLocal: false,
	})

	e.link = ethlink.New(uint32(cfg.MTU), cfg.MAC, true)

	// log.sniff, or -sniff on the command line, shows both directions, which
	// is the one thing a frame level hook cannot do: the netstack's sniffer
	// sees every packet the stack puts on the wire as well. It has to sit
	// above the ethernet wrapper, because it expects the link header to have
	// been parsed off the packet.
	var linkEP stack.LinkEndpoint = ethernet.New(e.link)
	if cfg.SniffPackets {
		linkEP = sniffer.NewWithPrefix(linkEP, "gw/")
	}

	if terr := e.stk.CreateNICWithOptions(nicID, linkEP, stack.NICOptions{Name: "guest"}); terr != nil {
		return nil, fmt.Errorf("create nic: %w", nsnet.ToError(terr))
	}

	if err := e.addAddress(cfg.GatewayIP, cfg.Mask, true); err != nil {
		return nil, err
	}
	dnsIPs := []net.IP{cfg.GatewayIP}
	if cfg.DNSIP != nil && !cfg.DNSIP.Equal(cfg.GatewayIP) {
		if err := e.addAddress(cfg.DNSIP, cfg.Mask, false); err != nil {
			return nil, err
		}
		dnsIPs = append(dnsIPs, cfg.DNSIP)
	}
	return dnsIPs, nil
}

// buildTunnel brings the VPN up and attaches it to the stack. It comes before
// any service: the resolvers the gateway asks are asked through it, and its
// routes are what a guest's destinations are matched against.
func (e *Engine) buildTunnel(conf *wgconf.Config) error {
	if err := e.checkTunnel(conf); err != nil {
		return err
	}
	warnIfShared(e.cfg.VPN, e.log)

	tunnel, err := vpn.New(conf, e.log)
	if err != nil {
		return err
	}
	// Named before it is attached so that Close, which New runs on any later
	// failure, can take it away again.
	e.tunnel = tunnel
	if err := tunnel.Attach(e.stk, vpnNIC); err != nil {
		return err
	}

	e.stk.SetRouteTable(routeTable(e.cfg.Subnet(), tunnel.Routes()))

	if e.cfg.Internet {
		// The guest uses addresses the stack was never told about, so the
		// interface has to accept them. That is only safe because buildStack
		// left HandleLocal off: turn that on and the stack would start throwing
		// this same traffic away as packets from ourselves.
		if terr := e.stk.SetPromiscuousMode(nicID, true); terr != nil {
			return fmt.Errorf("promiscuous mode: %w", nsnet.ToError(terr))
		}
		// Relays bind the address the guest dialled, an address the stack was
		// never told about.
		if terr := e.stk.SetSpoofing(nicID, true); terr != nil {
			return fmt.Errorf("spoofing: %w", nsnet.ToError(terr))
		}
	}
	return nil
}

// buildManager installs the guest facing side of the gateway: the manager that
// turns a guest's connection into something further out, the policy that
// decides which destinations it may dial, the list of addresses the gateway
// answers for itself, and the hook that decides what the link hands over.
func (e *Engine) buildManager(conf *wgconf.Config, o options) {
	cfg := e.cfg

	// The link is handed over as the way back out for frames the gateway
	// answers itself: an ICMP answer never reaches the stack, so it needs the
	// endpoint the stack would otherwise own.
	e.svcm = svc.NewManager(e.stk, nicID, o.dialer, e.log, svc.Limits{
		RelayIdle:     o.relayIdle,
		MaxConns:      o.maxConns,
		MaxPathsTotal: o.maxPathsTotal,
	}, e.link)
	e.svcm.EnableInternet(cfg.Internet)
	e.svcm.SetEgressPolicy(cfg.Egress)
	e.svcm.SetGuestSubnet(cfg.Subnet())
	e.svcm.SetEgress(e.tunnel)

	if cfg.Internet {
		// Worth one line at startup: the guest may reach out, but only through
		// the tunnel, and never at the reserved ranges even where the tunnel
		// would happily carry them.
		allow, deny := cfg.Egress.Custom()
		e.log.Info("egress: guest destinations",
			"tunnel_routes", conf.RouteStrings(), "reserved_denied", len(config.Reserved()),
			"allow", allow, "deny", deny)
		if cfg.Egress.LiftsReserved() {
			e.log.Warn("gateway.allow_egress reopens the reserved ranges",
				"allow", allow,
				"why", "a guest can now reach the host's own addresses and the metadata endpoint")
		}
	}

	e.svcm.Own(cfg.GatewayIP)
	if cfg.DNSIP != nil {
		e.svcm.Own(cfg.DNSIP)
	}
	// The segment's broadcast address is deliberately not claimed. Nothing
	// serves it, so a guest sending there is refused and counted like any other
	// destination in its own subnet, and a ping to it is refused outright: an
	// answer out of a broadcast address would teach the guest that a broadcast
	// is a machine. See Manager.echo.
	// The tunnel's addresses are ours too. Without this a guest dialling the
	// gateway's own tunnel address gets an on-demand relay that dials that
	// address straight back into the tunnel, holding a slot and a connection
	// against the caps, and reachable by the peer.
	for _, pre := range conf.Addresses {
		if pre.Addr().Is4() {
			e.svcm.Own(net.IP(pre.Addr().AsSlice()))
		}
	}

	e.link.SetInspect(e.inspect)
}
