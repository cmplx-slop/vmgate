package qemu

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseAddr(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Addr
		err  bool
	}{
		{in: "unix:/tmp/n.sock", want: Addr{Network: "unix", Name: "/tmp/n.sock"}},
		{in: "unix:@abstract", want: Addr{Network: "unix", Name: "@abstract"}},
		{in: "/tmp/n.sock", want: Addr{Network: "unix", Name: "/tmp/n.sock"}},
		{in: "./n.sock", want: Addr{Network: "unix", Name: "./n.sock"}},
		{in: "n.sock", want: Addr{Network: "unix", Name: "n.sock"}},
		{in: "tcp:127.0.0.1:12340", want: Addr{Network: "tcp", Name: "127.0.0.1:12340"}},
		{in: "tcp:12340", want: Addr{Network: "tcp", Name: ":12340"}},
		{in: "127.0.0.1:12340", want: Addr{Network: "tcp", Name: "127.0.0.1:12340"}},
		{in: "[::1]:12340", want: Addr{Network: "tcp", Name: "[::1]:12340"}},
		{in: "12340", want: Addr{Network: "tcp", Name: ":12340"}},

		{in: "", err: true},
		{in: "unix:", err: true},
		{in: "tcp:", err: true},
		{in: "tcp:host.example:service", err: true},
	} {
		got, err := ParseAddr(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("ParseAddr(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAddr(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseAddr(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	if _, err := ParseAddr(""); !errors.Is(err, ErrNoAddress) {
		t.Errorf("empty address error = %v, want ErrNoAddress", err)
	}
}

func TestRoundTripOverUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "n.sock")
	a, err := ParseAddr("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}

	l, err := a.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	// A second listener cannot open a socket that something is using.
	if _, err := a.Listen(); err == nil {
		t.Fatal("listening twice on a live socket succeeded")
	}

	c, err := a.Dial(t.Context())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if _, err := l.Accept(); err != nil {
		t.Fatalf("accept: %v", err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "n.sock")
	a := Addr{Network: "unix", Name: path}

	first, err := a.Listen()
	if err != nil {
		t.Fatal(err)
	}
	first.Close() // leaves the socket file behind

	second, err := a.Listen()
	if err != nil {
		t.Fatalf("restart over a stale socket file: %v", err)
	}
	second.Close()
}

// The link socket is the guest's network. A socket, or its directory, that
// other users can reach is an invitation to be the guest, so both are created
// private.
func TestListenKeepsTheSocketPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "gw.sock")

	a, err := ParseAddr("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.Listen()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("socket directory: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("socket directory mode = %o, want 700", got)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("socket mode = %o, want 600", got)
	}

	if a.SharedDir() {
		t.Error("a private directory was reported as shared")
	}
}

func TestSharedDir(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}

	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err) // /tmp itself, for the sake of the argument
	}

	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"unix:" + filepath.Join(shared, "gw.sock"), true},
		{"unix:" + filepath.Join(base, "gw.sock"), false},
		{"unix:@abstract", false},
		{"tcp:127.0.0.1:12340", false},
		{"unix:" + filepath.Join(base, "nowhere", "gw.sock"), false},
	} {
		a, err := ParseAddr(tc.address)
		if err != nil {
			t.Fatalf("%s: %v", tc.address, err)
		}
		if got := a.SharedDir(); got != tc.want {
			t.Errorf("%s: SharedDir = %v, want %v", tc.address, got, tc.want)
		}
	}
}

// A socket path we chose for ourselves has to sit in a directory only we can
// reach: in one that is open, or owned by somebody else, that somebody can
// connect to the socket or unlink it while it is live.
func TestListenPrivateMakesTheDirectoryOurs(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "gw.sock")

	a, err := ParseAddr("unix:" + path)
	if err != nil {
		t.Fatal(err)
	}
	l, err := a.ListenPrivate()
	if err != nil {
		t.Fatalf("listen private: %v", err)
	}
	defer l.Close()

	fi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("socket directory mode = %o, want 700", got)
	}
}

func TestListenPrivateRefusesWhatIsInTheWay(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := ParseAddr("unix:" + filepath.Join(blocker, "gw.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ListenPrivate(); err == nil {
		t.Fatal("a regular file standing in for the socket directory was accepted")
	} else {
		t.Logf("refused: %v", err)
	}
}
