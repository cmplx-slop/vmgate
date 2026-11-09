package svc

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/cmplx-slop/vmgate/internal/ethlink"
)

// A refusal has to be countable and, once, sayable: the stats line gives one
// number for every destination the gateway refused, and an operator looking at a
// guest that reaches nothing needs to know which destination and for what
// reason. It cannot be said for every packet, because a guest invents
// destinations faster than anyone reads a log.
func TestRefusalIsCountedEveryTimeAndSaidOnce(t *testing.T) {
	var buf bytes.Buffer
	m := NewManager(nil, 1, nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})), Limits{}, nil)
	defer m.Stop()

	for range 5 {
		m.refused(ethlink.Flow{DstIP: net.ParseIP("198.51.100.7"), DstPort: 443}, "the guest's own subnet")
	}
	if got := m.Denied(); got != 5 {
		t.Errorf("Denied = %d, want 5: every refusal has to count", got)
	}

	logged := buf.String()
	if n := strings.Count(logged, "level=WARN"); n != 1 {
		t.Errorf("%d lines at the level an operator sees by default, want 1:\n%s", n, logged)
	}
	if n := strings.Count(logged, "level=DEBUG"); n != 4 {
		t.Errorf("%d debug lines, want 4:\n%s", n, logged)
	}
	if !strings.Contains(logged, "to=198.51.100.7") || !strings.Contains(logged, "why=\"the guest's own subnet\"") {
		t.Errorf("the refusal does not name the destination and the reason:\n%s", logged)
	}
}

// A different destination is a different question, so it gets its own line, and
// past a bound they stop: the bound is what keeps a guest that sprays
// datagrams from turning the log into the problem.
func TestRefusalNotesAreBounded(t *testing.T) {
	var buf bytes.Buffer
	m := NewManager(nil, 1, nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})), Limits{}, nil)
	defer m.Stop()

	const ask = noticedMax + 40
	for i := range ask {
		ip := net.IPv4(198, 51, 100, byte(i))
		m.refused(ethlink.Flow{DstIP: ip, DstPort: 53}, "no route through the tunnel")
	}
	if got := m.Denied(); got != ask {
		t.Errorf("Denied = %d, want %d", got, ask)
	}
	if n := strings.Count(buf.String(), "level=WARN"); n != noticedMax {
		t.Errorf("%d named refusals, want the bound of %d", n, noticedMax)
	}
}
