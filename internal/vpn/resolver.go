package vpn

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"vmgate/internal/dns"
	"vmgate/internal/nsnet"
)

// Resolver returns the path the gateway's DNS server uses to ask one resolver: a
// fresh connected datagram socket through the tunnel, held to the timeout the
// query is being made within. A resolver that takes a query and goes quiet has
// to be given up on, or the guest's lookups stall behind it.
func (t *Tunnel) Resolver() dns.Dial {
	return func(addr *net.UDPAddr, timeout time.Duration) (dns.Datagram, error) {
		if addr.IP.To4() == nil {
			return nil, fmt.Errorf("vpn: resolver %s is not IPv4, and the tunnel speaks IPv4", addr)
		}
		u, err := t.dialUDP(net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port)))
		if err != nil {
			return nil, err
		}
		return &resolverPath{u: u, timeout: timeout}, nil
	}
}

// resolverWait is the fallback budget for one resolver, for a caller that has
// no opinion.
const resolverWait = 5 * time.Second

// resolverPath is one DNS exchange in flight through the tunnel.
type resolverPath struct {
	u       *nsnet.UDP
	timeout time.Duration
}

func (p *resolverPath) Write(b []byte) (int, error) { return p.u.Write(b) }

func (p *resolverPath) Close() error { return p.u.Close() }

// Read waits for the answer, and gives up after the timeout. The goroutine
// reading the socket is left to finish when Close runs: dns.exchange, the
// caller, closes the datagram as soon as the query is over either way.
func (p *resolverPath) Read(b []byte) (int, error) {
	wait := p.timeout
	if wait <= 0 {
		wait = resolverWait
	}

	type answer struct {
		n   int
		err error
	}
	ch := make(chan answer, 1)
	go func() {
		// Its own buffer: when the caller gives up on the timeout this
		// goroutine is still reading, and writing into the caller's slice after
		// they stopped waiting would be a race on memory they own. The socket
		// is closed underneath it, which is what lets it finish.
		own := make([]byte, len(b))
		n, _, err := p.u.Read(own)
		if n > 0 && n <= len(b) {
			copy(b, own[:n])
		}
		ch <- answer{n, err}
	}()

	select {
	case a := <-ch:
		return a.n, a.err
	case <-time.After(wait):
		return 0, fmt.Errorf("vpn: resolver did not answer within %v", wait)
	}
}
