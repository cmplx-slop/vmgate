package fixture

import (
	"fmt"
	"net"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"vmgate/internal/dns"
	"vmgate/internal/nsnet"
)

// ServeTCP starts a line oriented server beyond the tunnel: every line the
// guest sends comes back prefixed.
func (v *VPN) ServeTCP(ip string, port uint16, prefix string) {
	v.t.Helper()

	v.AddAddress(ip)
	l, err := gonet.ListenTCP(v.stk, nsnet.Full(farNIC, net.ParseIP(ip), port), header.IPv4ProtocolNumber)
	if err != nil {
		v.t.Fatalf("far listen tcp %s:%d: %v", ip, port, err)
	}
	v.t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()

				buf := make([]byte, 4096)
				var line []byte
				for {
					n, err := conn.Read(buf)
					if n > 0 {
						line = append(line, buf[:n]...)
						for {
							i := strings.IndexByte(string(line), '\n')
							if i < 0 {
								break
							}
							text := strings.TrimRight(string(line[:i]), "\r")
							line = line[i+1:]
							if _, err := fmt.Fprintf(conn, "%s%s\n", prefix, text); err != nil {
								return
							}
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

// ServeUDP starts a datagram server beyond the tunnel: each datagram comes back
// prefixed.
func (v *VPN) ServeUDP(ip string, port uint16, prefix string) {
	v.t.Helper()

	v.AddAddress(ip)
	u, err := nsnet.ListenUDP(v.stk, farNIC, net.ParseIP(ip), port)
	if err != nil {
		v.t.Fatalf("far listen udp %s:%d: %v", ip, port, err)
	}
	v.t.Cleanup(func() { _ = u.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := u.Read(buf)
			if err != nil {
				return
			}
			reply := append([]byte(prefix), buf[:n]...)
			if _, err := u.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
}

// ServeDNS starts a resolver beyond the tunnel that answers name with ip, which
// is what a test uses to check that the gateway's DNS went through the tunnel.
func (v *VPN) ServeDNS(ip string, answers map[string]string) {
	v.t.Helper()

	v.AddAddress(ip)
	u, err := nsnet.ListenUDP(v.stk, farNIC, net.ParseIP(ip), 53)
	if err != nil {
		v.t.Fatalf("far dns %s: %v", ip, err)
	}
	v.t.Cleanup(func() { _ = u.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := u.Read(buf)
			if err != nil {
				return
			}
			q, err := dns.ParseQuestion(buf[:n])
			if err != nil {
				continue
			}
			target := answers[strings.ToLower(strings.TrimSuffix(q.Name, "."))]
			if target == "" {
				target = answers["*"]
			}
			var reply []byte
			if ip := net.ParseIP(target); ip != nil {
				reply = dns.BuildAnswer(buf[:n], ip)
			} else {
				reply = dns.BuildNXDomain(buf[:n])
			}
			if _, err := u.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
}
