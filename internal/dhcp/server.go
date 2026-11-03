package dhcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Conn is the transport the server reads client packets from and writes
// replies to. The adapter in internal/engine implements it over a gVisor UDP
// endpoint, and the unit tests implement it over a slice of packets.
type Conn interface {
	Read(p []byte) (int, *net.UDPAddr, error)
	WriteTo(p []byte, to *net.UDPAddr) error
	Close() error
}

// Pool is a contiguous range of assignable addresses.
type Pool struct {
	Start net.IP
	Size  int
}

// Contains reports whether ip is inside the pool.
func (p Pool) Contains(ip net.IP) bool {
	if ip == nil || p.Size <= 0 {
		return false
	}
	off, ok := p.offset(ip)
	return ok && off >= 0 && off < p.Size
}

func (p Pool) offset(ip net.IP) (int, bool) {
	a, b := ip.To4(), p.Start.To4()
	if a == nil || b == nil {
		return 0, false
	}
	return int(ipU32(a) - ipU32(b)), true
}

func ipU32(b []byte) uint32 {
	var n uint32
	for _, c := range b {
		n = n<<8 | uint32(c)
	}
	return n
}

// At returns the i-th address of the pool.
func (p Pool) At(i int) net.IP {
	base := ipU32(p.Start.To4()) + uint32(i)
	return net.IPv4(byte(base>>24), byte(base>>16), byte(base>>8), byte(base)).To4()
}

// Lease is one address assignment.
type Lease struct {
	Client net.HardwareAddr
	IP     net.IP
	Expiry time.Time
}

func (l Lease) String() string {
	return l.Client.String() + " -> " + l.IP.String() + " (expires " + l.Expiry.Format(time.RFC3339) + ")"
}

// ServerConfig configures the server.
type ServerConfig struct {
	Gateway    net.IP
	DNS        []net.IP
	Mask       net.IPMask
	Pool       Pool
	LeaseTime  time.Duration
	RenewTime  time.Duration
	RebindTime time.Duration
	Domain     string
	MTU        uint32
	// PinMAC, when set, restricts the server to a single client.
	PinMAC net.HardwareAddr
	Logger *slog.Logger
}

// Server is a small DHCP server.
//
// The leases are kept twice over, by hardware address and by pool address,
// because both questions get asked on every request: "what does this client
// already have" and "is this address taken". With only the first index, the
// second costs a walk of the table for every address considered, and a client
// can choose how long that walk is.
type Server struct {
	cfg   ServerConfig
	mu    sync.Mutex
	byMAC map[string]*Lease
	byIP  map[string]string // pool address -> the client holding it
	next  int               // where freeAddress looks first next time
	now   func() time.Time
}

// NewServer returns a server for cfg.
func NewServer(cfg ServerConfig) *Server {
	if cfg.LeaseTime <= 0 {
		cfg.LeaseTime = 24 * time.Hour
	}
	if cfg.RenewTime <= 0 {
		cfg.RenewTime = cfg.LeaseTime / 2
	}
	if cfg.RebindTime <= 0 {
		cfg.RebindTime = cfg.LeaseTime * 7 / 8
	}
	return &Server{
		cfg:   cfg,
		byMAC: map[string]*Lease{},
		byIP:  map[string]string{},
		now:   time.Now,
	}
}

// Leases snapshots the current assignments.
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Lease, 0, len(s.byMAC))
	for _, l := range s.byMAC {
		out = append(out, *l)
	}
	return out
}

// Serve reads client packets until ctx is done or the connection fails.
func (s *Server) Serve(ctx context.Context, c Conn) error {
	buf := make([]byte, 1536)
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()
	for {
		n, from, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			if s.cfg.Logger != nil {
				s.cfg.Logger.Warn("dhcp read", "err", err)
			}
			continue
		}
		req, err := Parse(buf[:n])
		if err != nil {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Debug("dhcp dropped malformed packet", "err", err, "from", from)
			}
			continue
		}
		rep, ok := s.Handle(req)
		if !ok {
			continue
		}
		b := rep.Marshal()
		if b == nil {
			continue
		}
		to := s.replyTo(req, from)
		if err := c.WriteTo(b, to); err != nil {
			if s.cfg.Logger != nil {
				s.cfg.Logger.Warn("dhcp reply failed", "err", err, "to", to)
			}
			continue
		}
		if s.cfg.Logger != nil {
			s.cfg.Logger.Info("dhcp replied", "msg", TypeString(rep.Type()), "to", to, "yiaddr", rep.YourIP)
		}
	}
}
