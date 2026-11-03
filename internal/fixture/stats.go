package fixture

import (
	"fmt"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"

	"vmgate/internal/engine"
)

// DumpStackStats prints the netstack counters that explain a failure. They are
// the only way to see where a packet went: the gateway can drop it in a dozen
// places that leave no trace at the frame level. Netstack counters only show
// up here when they are non-zero, so a healthy run prints almost nothing.
func DumpStackStats(tb testing.TB, eng *engine.Engine) {
	tb.Helper()

	st := eng.StackStats()
	var b strings.Builder
	row := func(name string, c *tcpip.StatCounter) {
		if c == nil {
			return
		}
		if v := c.Value(); v != 0 {
			fmt.Fprintf(&b, "%s=%d ", name, v)
		}
	}

	row("ip.recv", st.IP.PacketsReceived)
	row("ip.valid", st.IP.ValidPacketsReceived)
	row("ip.bad-dst", st.IP.InvalidDestinationAddressesReceived)
	row("ip.bad-src", st.IP.InvalidSourceAddressesReceived)
	row("ip.malformed", st.IP.MalformedPacketsReceived)
	row("ip.delivered", st.IP.PacketsDelivered)
	row("ip.sent", st.IP.PacketsSent)
	row("ip.send-err", st.IP.OutgoingPacketErrors)

	row("arp.requests", st.ARP.RequestsReceived)
	row("arp.unknown-target", st.ARP.RequestsReceivedUnknownTargetAddress)
	row("arp.replies", st.ARP.RepliesReceived)
	row("arp.out-requests", st.ARP.OutgoingRequestsSent)
	row("arp.out-replies", st.ARP.OutgoingRepliesSent)
	row("arp.no-local-addr", st.ARP.OutgoingRequestInterfaceHasNoLocalAddressErrors)
	row("arp.dropped-requests", st.ARP.OutgoingRequestsDropped)

	row("tcp.valid-segments", st.TCP.ValidSegmentsReceived)
	row("tcp.invalid-segments", st.TCP.InvalidSegmentsReceived)
	row("tcp.segments-sent", st.TCP.SegmentsSent)
	row("tcp.send-errors", st.TCP.SegmentSendErrors)
	row("tcp.passive-opens", st.TCP.PassiveConnectionOpenings)
	row("tcp.active-opens", st.TCP.ActiveConnectionOpenings)
	row("tcp.failed-attempts", st.TCP.FailedConnectionAttempts)
	row("tcp.listen-overflow-syn", st.TCP.ListenOverflowSynDrop)
	row("tcp.resets-sent", st.TCP.ResetsSent)
	row("tcp.checksum-errors", st.TCP.ChecksumErrors)
	row("tcp.port-reservations", st.TCP.FailedPortReservations)

	row("udp.recv", st.UDP.PacketsReceived)
	row("udp.unknown-port", st.UDP.UnknownPortErrors)
	row("udp.buffer-errors", st.UDP.ReceiveBufferErrors)
	row("udp.sent", st.UDP.PacketsSent)

	row("transport.dropped", st.DroppedPackets)

	tb.Logf("stack stats: %s", strings.TrimSpace(b.String()))
}
