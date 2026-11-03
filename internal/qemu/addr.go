// Package qemu is the link to a guest: how QEMU's socket is spelled, dialled
// and defended, and how ethernet frames are delimited once the socket is open.
//
// QEMU can be either the client or the server:
//
//	-netdev stream,id=n0,addr.type=unix,addr.path=/tmp/vmgate.sock
//	    QEMU dials out, so vmgate listens (-listen unix:/tmp/vmgate.sock).
//
//	-netdev stream,id=n0,server=on,addr.type=inet,addr.host=127.0.0.1,addr.port=12340
//	    QEMU listens, so vmgate dials (-connect tcp:127.0.0.1:12340).
//
// Both that backend and the older "-netdev socket" multiplex whole ethernet
// frames onto one reliable byte stream by putting a 32 bit big endian length in
// front of each one: see net_stream_data_receive() (htonl(size)) and
// net_fill_rstate() in the QEMU sources.
//
// That is the only framing here on purpose. An earlier version also had a mode
// that concatenated frames and took each length out of the packet headers, and
// it cost more than it paid for: no QEMU invocation needs one, it put IPv4
// parsing inside the code whose job is to find frame boundaries, and it could
// not size a frame it did not recognise.
package qemu

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrNoAddress is returned for an empty address.
var ErrNoAddress = errors.New("no address given")

// socketMode and socketDirMode are what a link socket and its directory get
// created with. Whoever can write the directory can put a socket there before
// the gateway does, and whoever can reach the socket can connect to it and be
// the guest, so both default to the gateway's user alone. An operator who runs
// QEMU as a different user picks that arrangement explicitly with link.listen.
const (
	socketMode    os.FileMode = 0o600
	socketDirMode os.FileMode = 0o700
)

// Addr is a parsed endpoint specification.
type Addr struct {
	// Network is "unix" or "tcp".
	Network string
	// Name is the socket path for unix, host:port for tcp.
	Name string
}

// ParseAddr accepts the address forms vmgate understands:
//
//	unix:/path/to/sock, unix:@abstract
//	tcp:HOST:PORT, tcp:PORT
//	/path/to/sock (a path is always a unix socket)
//	HOST:PORT, or a bare PORT
func ParseAddr(s string) (Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Addr{}, ErrNoAddress
	}
	switch {
	case strings.HasPrefix(s, "unix:"):
		p := strings.TrimPrefix(s, "unix:")
		if p == "" {
			return Addr{}, fmt.Errorf("%w: empty unix socket path", ErrNoAddress)
		}
		return Addr{Network: "unix", Name: p}, nil
	case strings.HasPrefix(s, "tcp:"):
		return parseTCPPart(strings.TrimPrefix(s, "tcp:"))
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"), strings.HasPrefix(s, "@"):
		return Addr{Network: "unix", Name: s}, nil
	}
	// A bare "[::1]:1234" or "127.0.0.1:1234" is a TCP address; a bare path
	// without a colon is a unix socket. A bare number is a port, matching the
	// tcp:PORT spelling.
	if _, _, err := net.SplitHostPort(s); err == nil {
		return parseTCPPart(s)
	}
	if strings.Contains(s, ":") {
		return parseTCPPart(s)
	}
	if _, err := strconv.Atoi(s); err == nil {
		return parseTCPPart(s)
	}
	return Addr{Network: "unix", Name: s}, nil
}

func parseTCPPart(s string) (Addr, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// Allow ":1234" and "1234".
		if _, err := strconv.Atoi(s); err == nil {
			host, port = "", s
		} else {
			return Addr{}, fmt.Errorf("bad tcp address %q: %v", s, err)
		}
	}
	if _, err := strconv.Atoi(port); err != nil {
		return Addr{}, fmt.Errorf("bad tcp port in %q: %v", s, err)
	}
	return Addr{Network: "tcp", Name: net.JoinHostPort(host, port)}, nil
}

func (a Addr) String() string { return a.Network + ":" + a.Name }

// Dial connects to QEMU (which must be running with server=on).
func (a Addr) Dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, a.Network, a.Name)
}

// Listen waits for QEMU to connect. For unix sockets a stale socket file is
// removed first, which makes restarting vmgate painless.
func (a Addr) Listen() (net.Listener, error) {
	if path := a.socketPath(); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), socketDirMode); err != nil {
			return nil, fmt.Errorf("create socket directory: %w", err)
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			if probe := dialUnix(path); probe == nil {
				return nil, fmt.Errorf("%s is already in use by a live listener", path)
			}
			_ = os.Remove(path)
		}
	}
	lc := net.ListenConfig{}
	l, err := lc.Listen(context.Background(), a.Network, a.Name)
	if err != nil {
		return nil, err
	}
	if path := a.socketPath(); path != "" {
		_ = os.Chmod(path, socketMode)
	}
	return l, nil
}

// ListenPrivate is Listen for a socket whose path we chose ourselves, in which
// case the directory holding it has to be ours and nobody else's: a directory
// another user owns is one where they can unlink the socket while it is live,
// and a directory open to the group is one where they can connect to it. A path
// the operator wrote down is not ours to override, so that gets Listen and a
// warning instead.
func (a Addr) ListenPrivate() (net.Listener, error) {
	path := a.socketPath()
	if path != "" {
		if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
			return nil, err
		}
	}
	return a.Listen()
}

// ensurePrivateDir creates a socket directory only we can reach, and says
// plainly when something already there prevents that.
func ensurePrivateDir(dir string) error {
	// Create it first and judge it afterwards, rather than judging it only when
	// Stat said it was missing: between that answer and MkdirAll another user
	// can have made the directory, MkdirAll is then content to return no error,
	// and the socket lives in a directory they own and can unlink it from.
	if err := os.MkdirAll(dir, socketDirMode); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is in the way of the socket directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if ok && os.Geteuid() != 0 && st.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s belongs to another user: remove it or choose link.listen", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, socketDirMode); err != nil {
			return fmt.Errorf("make %s private: %w", dir, err)
		}
	}
	return nil
}

// socketPath is the filesystem path of a unix socket, empty for a tcp address
// and for the abstract namespace, which has no permissions to get wrong.
func (a Addr) socketPath() string {
	if a.Network != "unix" || strings.HasPrefix(a.Name, "@") {
		return ""
	}
	return a.Name
}

// SharedDir reports whether the directory the socket lives in is writable by
// anyone other than the gateway's user. Such a directory lets another local
// process take the socket's name before the gateway gets there, or connect to
// it afterwards and be the guest.
func (a Addr) SharedDir() bool {
	path := a.socketPath()
	if path == "" {
		return false
	}
	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false
	}
	return fi.Mode().Perm()&0o022 != 0
}

// dialUnix probes an existing socket; it returns nil when something is
// listening there.
func dialUnix(path string) error {
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

// IsStaleSocket reports whether err indicates a leftover socket file.
func IsStaleSocket(err error) bool {
	var serr *net.OpError
	if errors.As(err, &serr) {
		var sysErr *os.SyscallError
		if errors.As(serr.Err, &sysErr) {
			return errors.Is(sysErr.Err, syscall.EADDRINUSE)
		}
	}
	return errors.Is(err, syscall.EADDRINUSE)
}
