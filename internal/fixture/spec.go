package fixture

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tunnelSpec is one side of the pair, in the shape wg-quick writes.
type tunnelSpec struct {
	PrivKey   string
	IP        string
	Listen    int
	MTU       int
	DNS       []string
	PeerKey   string
	Endpoint  string
	Allowed   []string
	Keepalive int
}

func (s tunnelSpec) text() string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.PrivKey)
	fmt.Fprintf(&b, "Address = %s/32\n", s.IP)
	fmt.Fprintf(&b, "ListenPort = %d\n", s.Listen)
	fmt.Fprintf(&b, "MTU = %d\n", s.MTU)
	if len(s.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(s.DNS, ", "))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", s.PeerKey)
	if s.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", s.Endpoint)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(s.Allowed, ", "))
	if s.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", s.Keepalive)
	}
	return b.String()
}

// keyPair returns a base64 private key and its base64 public key.
func keyPair(t *testing.T) (priv, pub string) {
	t.Helper()

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	raw[0] &= 248
	raw[31] &= 127
	raw[31] |= 64

	var p [32]byte
	curve25519.ScalarBaseMult(&p, &raw)
	return base64.StdEncoding.EncodeToString(raw[:]), base64.StdEncoding.EncodeToString(p[:])
}

// stackCounters is a short summary of what the far stack did with the packets it
// saw, printed when a test fails.
func stackCounters(s *stack.Stack) string {
	st := s.Stats()
	return fmt.Sprintf("ip rx=%d delivered=%d sent=%d dropped=%d",
		st.IP.PacketsReceived.Value(), st.IP.PacketsDelivered.Value(),
		st.IP.PacketsSent.Value(), st.DroppedPackets.Value())
}
