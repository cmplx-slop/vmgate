package dhcp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cmplx-slop/vmgate/internal/testutil"
)

// The lease table is bounded by the pool, and so is the cost of one request. A
// client chooses its own hardware address, so "how many clients has this server
// seen" is not a number the operator set: with the table unbounded, every later
// DISCOVER pays for a walk over everything the gateway has ever handed out, and a
// guest with a loop turns the DHCP server into the most expensive thing in the
// process.
//
// A client with nothing to offer it is not answered at all, so "served" below
// means an address was actually handed out.
func TestLeaseTableIsBoundedByThePool(t *testing.T) {
	s := NewServer(ServerConfig{
		Gateway:   net.ParseIP("10.0.2.2"),
		Mask:      net.CIDRMask(24, 32),
		Pool:      Pool{Start: net.ParseIP("10.0.2.15"), Size: 4},
		LeaseTime: time.Hour,
	})

	served := 0
	for i := range 200 {
		mac := testutil.MAC(t, fmt.Sprintf("52:54:00:00:%02x:%02x", i, i%7))
		if _, ok := s.Handle(client(mac, Discover, uint32(i+1), nil)); ok {
			served++
		}
	}
	if served != 4 {
		t.Errorf("clients served = %d, want four, one per address in the pool", served)
	}
	if n := len(s.Leases()); n > 4 {
		t.Errorf("leases = %d, want at most one per address in the pool", n)
	}
}

// A lease whose time has passed is not a lease. Expired entries used to stay in
// the table forever, so a guest that rebooted with a new hardware address left
// one behind on every boot, and the table only ever grew.
func TestExpiredLeasesAreGivenBack(t *testing.T) {
	s := NewServer(ServerConfig{
		Gateway:   net.ParseIP("10.0.2.2"),
		Mask:      net.CIDRMask(24, 32),
		Pool:      Pool{Start: net.ParseIP("10.0.2.15"), Size: 2},
		LeaseTime: time.Hour,
	})

	at := time.Now()
	s.now = func() time.Time { return at }

	for _, mac := range []string{"52:54:00:00:00:01", "52:54:00:00:00:02"} {
		if _, ok := s.Handle(client(testutil.MAC(t, mac), Discover, 1, nil)); !ok {
			t.Fatalf("%s could not get an address from a pool of two", mac)
		}
	}

	at = at.Add(2 * time.Hour) // both leases have now expired

	for _, mac := range []string{"52:54:00:00:00:03", "52:54:00:00:00:04"} {
		if _, ok := s.Handle(client(testutil.MAC(t, mac), Discover, 2, nil)); !ok {
			t.Fatalf("%s could not get an expired address back", mac)
		}
	}

	if n := len(s.Leases()); n > 2 {
		t.Errorf("leases = %d, want the pool size, with the expired ones gone", n)
	}
}

// What a guest can exhaust with forged hardware addresses is the pool, so the
// right answer is a refusal. What must not come with it is a search that costs
// the pool for every entry in the table: that is CPU the gateway pays per frame,
// forever, because expired leases used to stay. A guest that wants its address
// guaranteed has guest_mac; this is about the cost of saying no.
func TestFullPoolIsRefusedQuickly(t *testing.T) {
	const poolSize = 4096

	s := NewServer(ServerConfig{
		Gateway:   net.ParseIP("10.0.2.2"),
		Mask:      net.CIDRMask(24, 32),
		Pool:      Pool{Start: net.ParseIP("10.0.2.15"), Size: poolSize},
		LeaseTime: time.Hour,
	})

	for i := range poolSize {
		mac := testutil.MAC(t, fmt.Sprintf("52:54:%02x:%02x:%02x:%02x", i>>24, i>>16, i>>8, i&0xff))
		s.Handle(client(mac, Request, uint32(i+1), s.cfg.Pool.At(i)))
	}

	start := time.Now()
	_, ok := s.Handle(client(testutil.MAC(t, "52:54:00:00:ff:ff"), Discover, 9999, nil))
	elapsed := time.Since(start)

	if ok {
		t.Error("a DISCOVER was answered from a pool with nothing left")
	}
	if elapsed > 150*time.Millisecond {
		t.Errorf("refusing one DISCOVER against a table of %d took %v: it should cost a scan "+
			"of the pool, not of the pool for every entry in the table", poolSize, elapsed)
	}
}
