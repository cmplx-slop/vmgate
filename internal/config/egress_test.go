package config

import (
	"net"
	"testing"
)

func TestEgressPolicy(t *testing.T) {
	p, err := ParseEgress(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"169.254.169.254", "169.254.0.0/16"}, // the cloud metadata endpoint
		{"127.0.0.1", "127.0.0.0/8"},
		{"0.0.0.0", "0.0.0.0/8"},
		{"224.0.0.251", "224.0.0.0/4"},
		{"255.255.255.255", "240.0.0.0/4"},
		{"100.64.0.1", "100.64.0.0/10"},
	} {
		if got := p.BlockedBy(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("%s blocked by %q, want %q", tc.ip, got, tc.want)
		}
	}

	// Ordinary destinations, including the private networks the guest shares
	// its gateway with, stay reachable: refusing those is the operator's call.
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "172.17.0.1", "10.0.0.2", "192.168.1.10"} {
		if !p.Allows(net.ParseIP(ip)) {
			t.Errorf("%s was refused by the default policy", ip)
		}
	}

	// A reserved range can be lifted, and any range can be added.
	p, err = ParseEgress([]string{"169.254.169.254"}, []string{"172.16.0.0/12", "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(net.ParseIP("169.254.169.254")) {
		t.Error("allow_egress did not lift the reserved range")
	}
	if p.Allows(net.ParseIP("169.254.1.1")) {
		t.Error("lifting one address should not open all of link-local")
	}
	if p.Allows(net.ParseIP("172.17.0.1")) || p.Allows(net.ParseIP("10.0.0.5")) {
		t.Error("deny_egress was ignored")
	}
	if !p.Allows(net.ParseIP("10.0.0.6")) {
		t.Error("a bare address in deny_egress must name only that address")
	}

	// And nonsense in either list is a startup error, not an open policy.
	for _, bad := range [][]string{{"not-a-network"}, {""}, {"10.0.0.0/64"}} {
		if _, err := ParseEgress(bad, nil); err == nil {
			t.Errorf("allow_egress %q was accepted", bad)
		}
		if _, err := ParseEgress(nil, bad); err == nil {
			t.Errorf("deny_egress %q was accepted", bad)
		}
	}
}

// A file can widen or narrow the policy, and a bad entry is refused.
func TestEgressFromTOML(t *testing.T) {
	cfg := loadTOML(t, "[gateway]\ndeny_egress = [\"172.16.0.0/12\"]\nallow_egress = [\"100.64.0.0/10\"]\n", Overrides{})
	if cfg.Egress.Allows(net.ParseIP("172.17.0.1")) {
		t.Error("deny_egress from the file was ignored")
	}
	if !cfg.Egress.Allows(net.ParseIP("100.64.0.1")) {
		t.Error("allow_egress from the file was ignored")
	}

	mustReject(t, "[gateway]\ndeny_egress = [\"wide open\"]\n")
}

func quote(s string) string { return "\"" + s + "\"" }

// A bare prefix length is refused in both lists: written in allow_egress it
// would reopen everything the built-in policy exists to keep shut, and that is
// far too easy a thing to type.
func TestEgressRejectsBarePrefix(t *testing.T) {
	for _, list := range [][]string{{"0"}, {"24"}, {"32"}} {
		if _, err := ParseEgress(list, nil); err == nil {
			t.Errorf("allow_egress %q was accepted", list)
		}
		if _, err := ParseEgress(nil, list); err == nil {
			t.Errorf("deny_egress %q was accepted", list)
		}
	}
}

// The policy knows when the operator has undone it, which is what lets the
// gateway say so at startup rather than discover it later.
func TestEgressLiftsReserved(t *testing.T) {
	for _, tc := range []struct {
		allow []string
		want  bool
	}{
		{nil, false},
		{[]string{"8.8.8.8"}, false},
		{[]string{"10.0.0.0/8"}, false},
		{[]string{"169.254.169.254"}, true},
		{[]string{"127.0.0.0/8"}, true},
		{[]string{"0.0.0.0/0"}, true},
	} {
		p, err := ParseEgress(tc.allow, nil)
		if err != nil {
			t.Fatalf("%v: %v", tc.allow, err)
		}
		if got := p.LiftsReserved(); got != tc.want {
			t.Errorf("allow_egress %v: LiftsReserved = %v, want %v", tc.allow, got, tc.want)
		}
	}
}
