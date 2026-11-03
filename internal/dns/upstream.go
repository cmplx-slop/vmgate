package dns

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"vmgate/internal/svc"
)

// resolver forwards a query verbatim and returns the response.
type resolver interface {
	Exchange(msg []byte) ([]byte, error)
}

// Datagram is one connected datagram path to a resolver: writes go to it, reads
// are its answers, and Close finishes the exchange. It is svc's type, aliased
// here so that a resolver and a relay's path out are described by the same three
// methods; svc says there why the shape is the one that matters.
type Datagram = svc.Datagram

// Dial opens a path to a resolver, bounded by timeout. The gateway supplies it,
// because the gateway is what decides how a query leaves: through the tunnel, or
// over the host's own network. Connected matters: a resolver's answer should
// only ever be readable by the query it answers.
type Dial func(addr *net.UDPAddr, timeout time.Duration) (Datagram, error)

// Failover tries each resolver in turn, starting where the last attempt
// succeeded.
type Failover struct {
	Servers []string

	// Timeout is how long each resolver is given before the next one is
	// tried. Zero means upstreamTimeout.
	Timeout time.Duration

	// Dial is how a resolver is reached. Without it the host's own network is
	// used; the gateway passes the tunnel's, so a guest's lookups leave the
	// same way its traffic does.
	Dial Dial

	mu  sync.Mutex
	idx int
}

// Exchange implements resolver.
func (f *Failover) Exchange(msg []byte) ([]byte, error) {
	f.mu.Lock()
	start := f.idx
	f.mu.Unlock()

	var lastErr error
	for i := range f.Servers {
		n := (start + i) % len(f.Servers)
		resp, err := (&udpResolver{Server: f.Servers[n], Timeout: f.Timeout, Dial: f.Dial}).Exchange(msg)
		if err == nil {
			f.mu.Lock()
			f.idx = n
			f.mu.Unlock()
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// SystemResolvers reads the host's resolver list, so the guest inherits the
// host's connectivity without any privileged operation. The fallback keeps the
// gateway usable on a host with no resolv.conf.
func SystemResolvers() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8:53"}
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if ip := net.ParseIP(fields[1]); ip != nil && ip.To4() != nil {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	if len(out) == 0 {
		return []string{"8.8.8.8:53"}
	}
	return out
}

// upstreamTimeout is how long a resolver gets to answer. Queries are answered
// on the goroutine that reads the guest's datagrams, so an upstream that goes
// quiet rather than refusing would stop the guest's DNS altogether, and
// Failover would never get as far as the next resolver.
const upstreamTimeout = 5 * time.Second

// udpResolver talks to one resolver. Without Dial it uses the host's network;
// with it, whatever path the gateway opened, which is how a guest's lookups end
// up going through the tunnel.
type udpResolver struct {
	Server string

	// Timeout bounds the whole exchange of the host path: connecting, querying
	// and waiting for the answer. Zero means upstreamTimeout. A Dial is
	// responsible for its own deadline instead.
	Timeout time.Duration

	// Dial opens the path to the resolver. See Dial.
	Dial Dial
}

func (u *udpResolver) timeout() time.Duration {
	if u.Timeout > 0 {
		return u.Timeout
	}
	return upstreamTimeout
}

// Exchange implements resolver.
func (u *udpResolver) Exchange(msg []byte) ([]byte, error) {
	wait := u.timeout()

	addr, err := net.ResolveUDPAddr("udp", u.Server)
	if err != nil {
		return nil, err
	}
	if u.Dial != nil {
		return exchange(u.Dial, addr, wait, msg)
	}

	conn, err := net.DialTimeout("udp", u.Server, wait)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Connecting in time says nothing about answering in time: a resolver that
	// takes the query and then goes silent has to be given up on too.
	if err := conn.SetDeadline(time.Now().Add(wait)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// exchange runs one query over a path the caller opened, with wait as the
// budget for the whole exchange: a resolver that swallows a query has to be
// given up on, or the guest's DNS stalls behind it.
func exchange(dial Dial, addr *net.UDPAddr, wait time.Duration, msg []byte) ([]byte, error) {
	conn, err := dial(addr, wait)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ParseResolvers turns a comma separated list of resolver addresses into
// "host:port" targets suitable for udpResolver. A bare address gets port 53.
//
// A name is refused, not looked up. The only resolver this process has lives
// inside the tunnel, so resolving an upstream would be the one DNS query that
// goes out through the host's connection, and the address that came back might
// not be reachable through the tunnel at all. Saying which address is meant
// costs the operator one line and keeps the promise the tunnel is there to keep.
func ParseResolvers(list string) ([]string, error) {
	var out []string
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port := entry, "53"
		if h, p, err := net.SplitHostPort(entry); err == nil {
			host, port = h, p
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("DNS server %q is a name: name its address, which is what the tunnel carries", entry)
		}
		if _, err := strconv.Atoi(port); err != nil {
			return nil, fmt.Errorf("bad DNS server port in %q", entry)
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no DNS servers given")
	}
	return out, nil
}
