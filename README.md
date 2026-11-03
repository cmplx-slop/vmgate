# vmgate

A rootless, userspace network for QEMU guests, in the spirit of
[passt](https://passt.top) and QEMU's `-netdev user`, but built on
[gVisor's netstack](https://gvisor.dev) instead of a tap device — and with every
guest destination reached through a WireGuard tunnel that lives in the same
process, so the host's own connection is never the path a VM's traffic takes.

One Go process, no root, no `CAP_NET_ADMIN`, no tap interface, no bridge, no
`wg-quick`. The guest believes it is on an ethernet segment with a gateway. The
gateway terminates what the guest starts inside its own netstack and sends it out
through wireguard-go, encrypted, as an ordinary user process; the connections the
operator names by hand are still ordinary host sockets.

```
   guest (virtio-net)              vmgate                          the VPN server
   ┌───────────────┐  frames over  ┌────────────────────────┐      ┌──────────┐
   │ Linux stack   │◀──socket────▶ │ gVisor netstack        │      │          │
   │ 10.0.2.15/24  │ (len32 framed)│ 10.0.2.2 gateway       │◀────▶│ wg       │
   └───────────────┘               │ + DHCP + DNS           │ udp  │          │
                                   │ + a vpn NIC            │      └──────────┘
                                   │ + forwards ────────────┼─┐ host sockets
                                   │ + services ────────────┼─┴──────────▶ host kernel
                                   └────────────────────────┘
```

A guest destination is routed by the tunnel's `AllowedIPs` and by nothing else.
There is no route out that does not go through the tunnel, and a destination the
peer will not carry is refused, not leaked some other way.

## Quick start

Terminal 1 — vmgate listens, QEMU dials out. The configuration is one TOML
file, `examples/vmgate.toml`, and that file names a `vpn.conf` in wg-quick
syntax, `examples/vpn.conf`:

```sh
go build -o vmgate ./cmd/vmgate
./vmgate -config examples/vmgate.toml
```

The example tunnel's keys are placeholders, so it starts and never completes a
handshake, and the log says so after a few seconds. Point `[vpn] conf` at a VPN
you can actually reach before expecting a guest to see anything.

Terminal 2 — QEMU:

```sh
qemu-system-x86_64 \
  -object memory-backend-ram,size=2G -machine q35 -enable-kvm \
  -drive file=guest.qcow2,if=virtio,format=qcow2 \
  -netdev stream,id=n0,addr.type=unix,addr.path=/tmp/vmgate.sock \
  -device virtio-net-pci,netdev=n0
```

Inside the guest: `dhclient eth0` (or `systemd-networkd`) picks up
`10.0.2.15/24` with gateway `10.0.2.2` and resolver `10.0.2.3`. From the host:
`ssh -p 2222 127.0.0.1` reaches the guest's sshd. From the guest:
`curl http://10.0.2.2/` reaches the HTTP server on the host's port 8080, and
`wget -qO- http://1.1.1.1/` leaves through the tunnel.

The other direction, which is handy when QEMU should start first — the file
says `listen`, the command line turns it into `connect`:

```sh
# QEMU listens
qemu-system-x86_64 ... \
  -netdev stream,id=n0,server=on,addr.type=unix,addr.path=/tmp/vmgate.sock \
  -device virtio-net-pci,netdev=n0

# vmgate dials in and keeps reconnecting
./vmgate -config examples/vmgate.toml -connect unix:/tmp/vmgate.sock
```

`examples/run-qemu.sh` puts both sides together; `VPN_CONF=path/to/vpn.conf`
picks the tunnel.

Older QEMU without `-netdev stream` can use `-netdev socket`, which speaks the
same framing.

## Configuration

Everything is in the TOML file named by `-config`, which is required: the
gateway never runs on settings nobody wrote down. A setting the file has and the
program does not is a startup error, so a typo is caught at startup instead of
being silently ignored. Every key is optional; the values below are the
defaults unless stated.

```toml
[link]
listen  = "unix:/tmp/vmgate.sock"      # or connect = "tcp:127.0.0.1:12340"
                                       # unset: a private socket in
                                       # $XDG_RUNTIME_DIR

[network]
gateway  = "10.0.2.2"
dns_ip   = "10.0.2.3"
guest_ip = "10.0.2.15"
netmask  = "255.255.255.0"             # also accepted: 24, or 10.0.2.0/24
mtu      = 1500                        # lowered to the tunnel's when smaller
domain   = "vmgate"
# mac       = "52:54:00:00:02:02"      # derived from the gateway address
# guest_mac = "52:54:00:12:34:56"      # pin the lease and the forwards

[dhcp]
enabled    = true
lease_time = "24h"                     # any Go duration
pool_size  = 16

[vpn]
conf = "vpn.conf"                      # required; relative to this file

[gateway]
internet  = true                       # guest destinations get a tunnel
allow_egress = []                      # ranges the guest may reach, reserved
deny_egress  = ["192.168.0.0/16"]      #   ones included, or refuse more

[dns]
# upstreams = ["1.1.1.1", "8.8.8.8:5353"]   # default: DNS= from vpn.conf, and
#                                           # addresses only: a name could only
#                                           # be looked up outside the tunnel
map_hosts = ["host.local"]             # answered with the gateway address

[[forward]]                            # host socket dialled into the guest
host_addr  = "127.0.0.1"
host_port  = 2222
guest_addr = "10.0.2.15"               # default: network.guest_ip
guest_port = 22
proto      = "tcp"                     # or udp

[[service]]                            # gateway port dialled on the host
guest_port = 80
host_addr  = "127.0.0.1"
host_port  = 8080
```

Only the socket, the tunnel file and the logging can also be given on the
command line, because those are what change between runs of the same guest; each
one replaces what the file said, and `-listen`/`-connect` also clear the other
end of the link:

| flag | overrides |
| --- | --- |
| `-config FILE` | the whole file (required) |
| `-listen ADDR` | `link.listen` — wait for QEMU (`unix:PATH`, `/path`, `tcp:HOST:PORT`, `HOST:PORT`) |
| `-connect ADDR` | `link.connect` — dial QEMU, which must run with `server=on`; retried with backoff |
| `-vpn FILE` | `vpn.conf` — a different tunnel for the same guest; the path is the shell's, not the file's |
| `-v N` | `log.verbosity`: 0 errors, 1 info (default), 2 debug |
| `-sniff` | `log.sniff` — log every packet in both directions (netstack sniffer) |

`vmgate -h` prints the same list and the smallest useful file.

## The tunnel

A `vpn.conf` in wg-quick syntax is the whole VPN setup: the same file
`wg-quick up` would take, read by this process instead of by a shell script. No
`wg`, no `wg-quick`, no kernel interface, no `root`.

```toml
[vpn]
conf = "vpn.conf"        # required. No tunnel, no start: a guest would have
                         # nowhere to go, and falling back to the host's own
                         # connection is exactly what this is here to prevent
```

`examples/vpn.conf` is an annotated one. What the file means here:

| wg-quick entry | what vmgate does with it |
| --- | --- |
| `PrivateKey`, `ListenPort` | the tunnel's key and the UDP port it receives on; `0` lets the host pick one, and the startup log says which |
| `Address` | the address the tunnel presents, and the source address of everything the guest sends. Written `10.8.0.2/24` it means that address on that network: the host bits are kept. None of them may be inside the guest's network and none may be the same address twice; every entry is checked, not just the first, because one address both sides answer for is a loop waiting to happen |
| `AllowedIPs` | the gate. These destinations have a route to the tunnel; everything else has no route and is refused. A `0.0.0.0/0` therefore does not hand the guest the host's networks: the egress policy still refuses the reserved ranges |
| `DNS` | asked from inside the tunnel, and used for the guest's lookups unless `dns.upstreams` names others. Must be addresses: there is no resolver to ask before the tunnel exists |
| `MTU` | 1420 when left out, and between 1280 and 1500: a bigger number does not carry more, it only multiplies what one authenticated peer can make this process hold. A `network.mtu` bigger than the tunnel's is lowered to it, so guests do not fragment on the way in |
| `Endpoint`, `PublicKey`, `PresharedKey`, `PersistentKeepalive` | the peer, as expected. `Endpoint` may be a name, resolved once by the host at startup |
| `Table`, `Fwmark`, `PreUp`, `PostUp`, … | accepted and ignored: those are instructions for a kernel side that does not exist here |

Exactly one `[Peer]`, because that is what routing one VM through one VPN means;
more is a startup error rather than a surprise. IPv6 is read and ignored.
Unknown keys other than the kernel instructions are refused. The private key is
never logged: the startup line names the peer by a short form of its public key
and the endpoint it dials, and the stats line reports that endpoint, how long
ago the peer last answered, the bytes through the tunnel, and why anything was
refused.

The tunnel is a NIC of the same netstack the guest hangs off, so the routing
decision is the stack's rather than a special case in the relay code, and the
guest's packets are encrypted by a userspace wireguard implementation with no
file descriptor and no device anywhere in the path.

## What the guest is told

| item | default | setting |
| --- | --- | --- |
| guest address | `10.0.2.15/24` | `network.guest_ip`, `network.netmask` |
| gateway (vmgate itself) | `10.0.2.2` | `network.gateway` |
| resolver | `10.0.2.3` | `network.dns_ip` |
| gateway MAC | derived from the gateway IP (`52:54:00:x:y:z`) | `network.mac` |
| lease time, domain, MTU | 24 h, `vmgate`, 1500, or the tunnel's MTU if smaller | `dhcp.lease_time`, `network.domain`, `network.mtu` |

The addresses follow the slirp/passt conventions, so guest images and existing
documentation keep working. The resolver the lease names is always the gateway,
not the VPN's: the gateway answers the synthetic `dns.map_hosts` names itself and
forwards everything else through the tunnel, which a guest could not do if it
were pointed at the VPN resolver directly.

## How it works

* **The link.** `-netdev stream` hands us whole ethernet frames over a socket,
  each preceded by a 4-byte big-endian length (`internal/qemu`).
  `internal/ethlink` is a headerless `stack.LinkEndpoint` that reads those
  frames and hands them to gVisor's `link/ethernet` wrapper, which builds and
  parses the ethernet header itself — so ARP works exactly the way the stack
  expects. Frames shorter than 60 bytes are padded on the way out, because a
  real NIC does that and guests expect it. A frame written to the guest waits at
  most two seconds for the guest to take it, and a guest that will not take
  frames is disconnected rather than waited for; see *A guest that stops taking
  frames is disconnected* below.

* **The stack.** Two NICs and one route table: the guest's link (NIC 1) and the
  tunnel (NIC 2). The table is guest subnet → the link, then the peer's
  `AllowedIPs` → the tunnel, then the default → the link, in that order, because
  this netstack's route lookup is first-match rather than longest-prefix. The
  gateway answers ARP, DHCP, DNS and any `[[service]]` port with listeners
  created inside the netstack (`internal/svc`, `internal/dhcp`, `internal/dns`).

* **The tunnel.** `internal/wgconf` parses and validates the wg-quick file,
  `internal/vpn` builds the wireguard-go device and joins it to the netstack
  with a small `tun.Device` shim whose interface is a `channel.Endpoint`: what
  wg decrypts is injected as an inner packet, and what the stack routes to that
  NIC is handed to wg to encrypt. The shim accepts only a well-formed IPv4
  packet of a sane length aimed at an address the tunnel owns, because the peer
  is only marginally less hostile than the guest; everything else is counted and
  dropped. Routes come from `AllowedIPs`, and the link and DHCP MTU come from
  the tunnel's.

* **Guest to anywhere.** With `gateway.internet`, before a frame is delivered to
  the stack the link layer inspects it (`ethlink.Classify`); if the guest is
  starting a flow to an address we do not serve, a listener for that exact
  address and port is created first, so the very first SYN is not lost. The
  relay then dials the same address *from inside the stack*, on the tunnel NIC,
  with the socket pinned to that interface: the route table decides whether the
  destination can be reached at all. Because the stack has to accept frames and
  bind addresses it does not own, the guest NIC runs with promiscuous mode and
  address spoofing on.

* **Ping.** An ICMP echo is answered at the frame level rather than inside the
  stack, and that is worth saying plainly because it looks like duplicated work.
  The netstack has an IPv4 echo responder built into its network layer, always on
  and impossible to switch off; on the guest interface, which is promiscuous so
  that relays can bind the addresses the guest dialled, that responder accepts an
  echo for *any* address and answers it, spoofed from the address that was
  pinged. A guest pinging a host the tunnel refuses to carry would be told it
  answers. So `Inspect` takes an echo away from the stack (`ethlink.ParseEcho`):
  the gateway answers its own addresses, including the tunnel's, and relays the
  rest through one socket per guest identifier, dialled from inside the stack on
  the tunnel NIC so `AllowedIPs` decides whether a ping can leave at all and only
  that host's answers come back. `icmp_answered` and `icmp_relayed` in the status
  line split the two. A VPN peer pinging the gateway's tunnel address is left to
  the responder: the tunnel interface is not promiscuous, so there it only
  answers addresses the gateway really owns. A request whose IPv4 header or ICMP
  checksum does not add up is refused rather than answered, and counted in
  `denied`: these are the frames the gateway takes away from the stack, so for
  them it is the receiver, and the only one that can tell.

* **Host to guest, and the ports the operator names.** `[[forward]]` opens a
  host listener and dials into the guest with `gonet.DialTCPWithBind`, appearing
  as the gateway address (`svc.Forwarder`). `[[service]]` connects to a host
  endpoint the configuration named. Those keep using the host's own sockets
  whatever the tunnel does: the tunnel is for a guest's destinations, not for
  connections someone wrote down. One
  `[[forward]]` bridges at most 64 host connections at a time; the rest are
  closed at once and counted in `forward_refused`, because a host socket is the
  one thing on this list that is not the guest's to spend.

* **Checksums.** The endpoint advertises RX checksum offload, because a
  virtio-net guest leaves the checksum to the device and QEMU drops the hint
  when it writes the frame. TX offload is *not* advertised, so the stack
  computes checksums and the guest can validate them in software. The frames the
  gateway answers for itself are the exception: an echo never reaches the
  network layer, so for those the sums are checked here and one that does not
  add up is refused.

* **Framing.** Frames are length prefixed, which is what `-netdev stream` and
  `-netdev socket` both speak, so there is one framing and no setting for it.
  There used to be a second one that took each length out of the packet headers
  for a stream with no prefix; nothing speaks that, and it meant the code that
  finds frame boundaries also parsed IPv4 and refused to size what it did not
  recognise.

## Testing

`make test` runs the suite without QEMU and without a VPN to dial: the fixture
runs a real wireguard-go tunnel to a second wireguard-go device, and joins the
gateway's netstack to a second gVisor netstack over an in-memory frame pipe; the
two together stand in for "the internet". So ARP, DHCP, TCP, UDP, DNS, both
forwarding directions, the tunnel and the AllowedIPs gate are exercised end to
end, with the pretend guest validating every checksum the gateway emits.

```
internal/config  the file format: defaults, every section, overrides, and the
                 values that are refused, including a missing vpn.conf
internal/dhcp    four way handshake, pool exhaustion, NAK, release
internal/dns     synthetic hosts, resolver failover, and the reply bytes: the
                 counts against the records that follow them, the question
                 carried back untouched, no EDNS0 record echoed, and what each
                 broken query gets
internal/ethlink frame classification, including VLAN tags and rejects, and the
                 echo codec: round trip, both checksums as a receiver checks
                 them, one VLAN tag looked through, and the rejects (fragments,
                 IP options, a wrong total length, anything that is not an echo)
internal/nsnet   that a dialled socket leaves by the interface it is pinned to,
                 and that it cannot reach a destination that interface has no
                 route for: the two halves of the AllowedIPs gate, at the level
                 of the socket helper. The echo socket is checked the same way,
                 plus what it puts on the wire (the stack's identifier, the
                 sequence asked for) and that it reads only answers carrying its
                 own identifier
internal/qemu    address forms, socket reuse, stale socket replacement, the one
                 framing, runt padding, close unblocks the reader
internal/vpn     the shim's filter (shape, length, and a destination the tunnel
                 owns, counted apart), its copy, its oversize drop, its MTU and
                 its close, and a configuration too incomplete to build a tunnel
internal/wgconf  wg-quick parsing: one peer, IPv4, DNS as addresses, an address
                 that keeps its host bits and an AllowedIPs prefix that loses
                 them, the MTU bounds, the kernel instructions that are ignored,
                 and no key in an error or in String()
internal/engine  gateway service over TCP and UDP, internet TCP and UDP relay
                 through the tunnel, a TLS handshake and a 24 KiB exchange
                 across it in both directions and from a guest whose packets are
                 larger than the tunnel, a destination outside AllowedIPs, a
                 destination on the guest's own segment, the gateway's own
                 tunnel address, DNS through the tunnel, the MTU lowered to the
                 tunnel's, ping answered for the gateway's own addresses and
                 answered only once, ping relayed and answered by whoever is
                 out there, ping the tunnel does not carry and ping into the
                 guest's own segment both silent, inbound forward, DHCP from
                 raw frames, no-internet, and one test over a real unix socket
                 with QEMU's framing; security_test.go adds the
                 egress policy, the relay, connection and datagram path caps,
                 and relays and translations surviving (or not) a guest
                 reconnect, which fixture.Reconnect drives; the internal tests
                 add the order of the route table, every tunnel address being
                 checked against the guest's subnet, and which resolver list
                 wins
internal/svc     the host datagram pipe's peer pinning, a UDP relay's path out
                 through a stand-in tunnel, the same for an echo: answered
                 locally with the request's identifier and hardware address,
                 relayed through one path per guest identifier, and refused
                 without an answer for a destination with no route, one in the
                 guest's own segment, or one the egress policy names; and that
                 refusals are counted every time and named once. forward_test.go
                 adds the ceiling one [[forward]] carries on host connections,
                 and that room comes back when a connection finishes
internal/testutil the plumbing a test cannot do without and internal/fixture
                 cannot lend it, because that sits above the package asking:
                 waiting for something asynchronous, a spare port, a hardware
                 address. What is deliberately missing is packet builders, so
                 that two tests writing the same wire format are two
                 implementations of it
```

When an engine test fails it prints the netstack's counters
(`internal/fixture.DumpStackStats`), which is the only way to see where a packet
was dropped. `VMGATE_TEST_LOGS=1` turns the gateway's own log on.

`make race` reruns everything under the race detector.

## Security posture

The guest is assumed hostile: everything on the link is chosen by whoever runs
the guest, and the gateway holds a host socket, so the two are kept apart by
policy rather than by trust. The VPN peer is treated nearly the same way: it is
a network we do not control, on the other end of a tunnel we do not control.

* **The tunnel is the only way out.** A guest destination is routed by the
  tunnel's `AllowedIPs`, and every socket the gateway dials with is pinned to
  the tunnel NIC, so even a peer whose `AllowedIPs` are `0.0.0.0/0` cannot be
  used to reach something the tunnel does not carry. A destination with no route
  is refused and counted in `denied`, which the stats line prints; the first
  refusal of a given address is also said at the default verbosity, naming it and
  the reason, and the rest are left to the debug log (`-v 2`) so a guest spraying
  datagrams cannot fill it. How that refusal looks from the guest depends on the
  protocol: a refused TCP connection is reset and a refused UDP datagram answered
  with an unreachable, because the frame still reaches the stack and finds no
  listener there, while a refused ping goes unanswered — there is no listener to
  refuse it, and answering a ping for an address the gateway does not serve is the
  reachability lie this section is about. There is no configuration that falls
  back to the host's connection: with no `vpn.conf` the gateway refuses to start.

  A refusal that happens *inside* an on-demand relay looks different, and it is
  the shape an operator hears about: the listener for the destination was put
  there when the SYN arrived, so the guest's connection opens, its writes are
  accepted, and the connection is closed once the dial through the tunnel fails —
  because the tunnel has no route for the address, or because nothing behind it
  answers before the gateway gives up. A TLS client reports that as an unexpected EOF
  in the middle of the handshake, not as a network failure, so the log line
  (`internet: refused`, naming the address and the reason) is what makes the
  guest's complaint answerable.
* **The gateway decides where a guest may go, not the guest.** An on-demand
  relay only appears if the destination passes the egress policy
  (`internal/config/egress.go`), which sits *inside* the routing decision:
  loopback, link-local (where the cloud metadata endpoint lives), `0.0.0.0/8`,
  `100.64.0.0/10`, multicast and `240.0.0.0/4` are refused unless
  `gateway.allow_egress` names them, and `gateway.deny_egress` refuses more.
  Entries are an address or a CIDR, never a bare prefix length:
  `allow_egress = ["0"]` would mean everything, and that is too easy to write by
  accident. Private networks are not refused by default: reaching a lab network
  is a normal thing to want. An `allow_egress` that reopens one of the reserved
  ranges is reported at startup.
* **Ping is decided in the same place, not by the netstack.** gVisor's network
  layer has an IPv4 echo responder that cannot be switched off, and on a
  promiscuous interface it answers an echo for any address at all, spoofed from
  the address that was pinged — a reachability lie that would quietly undo both
  the routing rule above and the egress policy. An echo is therefore taken from
  the stack before the network layer sees it and decided here: the gateway's own
  addresses, including the tunnel's, are answered; the guest's own segment, a
  refused range, and any address the tunnel does not carry are not; nor is a
  broadcast, limited or of the guest's own segment, because there is no single
  address to answer from. A fragment of an ICMP datagram is refused too: the
  stack would put it back together and answer it, so splitting a ping is not a
  way past any of the above, and `denied` counts it, as does a request whose
  checksums do not add up: the gateway took these frames away from the stack, so
  for them the gateway is the receiver and checking them is its job.
  `icmp_answered` and `icmp_relayed` in the stats line say which pings were
  answered here and which left through the tunnel, and `link_held` counts the
  frames taken away from the stack this way.
* **What the peer may send is checked, and where it may send it.** The tunnel's
  shim injects only a well-formed IPv4 packet whose declared length matches the
  bytes, fits the interface MTU, and is aimed at an address the tunnel owns.
  Anything else is dropped before the network layer sees it, and counted by
  reason: `vpn_refused` for a packet that is not a packet, `vpn_misaimed` for a
  well-formed one aimed somewhere else. The tunnel therefore carries traffic for
  the tunnel's own addresses and nothing else: not the guest's DHCP pool, not a
  relay a guest had opened, not the gateway's listeners. gVisor's IPv4 layer also
  refuses a destination that interface does not own, which makes the check a
  second line rather than the only one; it is the line that holds if the tunnel
  interface ever becomes promiscuous.
* **A guest cannot reach its own segment through the VPN.** A destination inside
  the guest's subnet is refused before a relay appears, so the peer cannot be
  handed an address on the guest's LAN and answer for it. The tunnel's own
  addresses are treated the same way: they belong to the gateway, and are not
  something to dial back into the tunnel.
* **A relay, and every connection running through it, belongs to one guest
  session.** An unused relay is taken away after a minute, and QEMU
  disconnecting closes the relays and the translations: a guest that vanishes
  mid-connection cannot leave the gateway holding sockets and connection
  budget, so a guest reboot cannot lock out the next guest or the next boot. A
  ping relay is keyed by the guest that asked as well as by the destination and
  the identifier, because an identifier is one guest's invention: two guests
  pinging the same host with the same identifier get one path each, and neither
  sees the other's answers. The link runs one session at a time, and a second
  connection is refused rather than sharing it.
* **A guest that stops taking frames is disconnected.** A guest whose device has
  stopped is a different problem from a guest that has vanished, and has to be
  handled on its own terms: the gateway answers ARP, DHCP and its own ping
  replies on the goroutine that read the frame, so a guest that will not take
  frames stops being read as well, and nothing about the session says so. The
  frame stream waits two seconds for one frame; a wait that runs out is taken as
  a link that cannot be written again, so the rest of that session's frames are
  refused at once, the transport is closed, and the session ends with everything
  it was holding. `dropped` counts the frames that could not be written, and the
  line that ends the session says the guest stopped taking frames rather than
  that it disconnected.
* **Translation is bounded.** 256 splices at a time across the gateway, 32 host
  sockets per UDP relay, 1024 datagram paths across all of them, printed as
  `paths` in the stats line, and 128 pings in flight inside the relay table's
  2048 slots. The per-relay number alone multiplies into tens of thousands of
  host sockets, and pings need a number of their own because a ping is the
  cheapest thing a guest can ask for: one frame, no handshake, and the source
  address is the guest's to invent. Left to the table's own cap, one guest with
  a loop would fill it with pings, and the guest that came next could not open a
  connection. A guest invents its own source addresses, so
  nothing above the gateway can tell it how many paths it may open. That budget
  is shared with the paths an operator's `[[service]]` UDP listener opens, so a
  guest spraying datagrams can starve one of those services: a POC trade-off,
  and `paths` is the number that shows it. Host connections get TCP keepalive,
  so a peer that vanishes without saying so cannot hold a socket and two
  goroutines forever.
* **A UDP reply may only come from the peer that was dialled.** Every datagram
  path is connected or pinned: a relay aimed at a host endpoint the operator
  named drops a datagram whose source is not that endpoint, so nobody who can
  merely see the gateway's ephemeral socket can put bytes into a guest's flow.
* **The link socket is the guest's network**: whoever can write to it *is* the
  guest. The default lives in `$XDG_RUNTIME_DIR`, or a `0700`
  `/tmp/vmgate-<uid>` directory when the system has no runtime directory,
  and the socket itself is mode `0600`. That directory has to be ours: if
  something else owns it or a file stands where it should be, the gateway
  refuses to start rather than bind inside someone else's directory. A
  `link.listen` the operator named inside a directory other users can write to
  logs a warning instead, because it is their choice. A `tcp:` link is
  unauthenticated plaintext frames: use one on loopback or on a network you
  already trust. Nothing on that link contradicts a frame about where it came
  from, either: the gateway's replies are addressed to whatever source the
  frame carried, so a guest that claims another guest's address, or the host's,
  can have answers aimed there. There is no point-to-point peer to validate
  against on a frame stream; `network.guest_mac` is the closest thing to it,
  pinning the lease and the host forwards to one hardware address.
* **A host-facing forward has a ceiling of its own.** Each `[[forward]]` bridges
  at most 64 host connections at a time: those are descriptors and goroutine
  pairs on the machine running the gateway, and the guest is not the one paying
  for them. A connection past the ceiling is closed as it is accepted, counted
  in `forward_refused` and said in the debug log, where a flood cannot fill the
  default log; `forward_conns` reports how many are being carried.
* The private key stays in the tunnel. It is never logged, never returned by the
  stats the gateway reports, and the wg-quick file is read once at startup.

## Traps worth knowing

These cost real debugging time and are easy to reintroduce:

* **wireguard-go needs `dev.Up()` after the device has been given to the
  stack**, and setting `private_key` over its IPC interface does not do it.
  Without `Up()` the peer objects are never started, so a handshake is never
  attempted and every symptom looks like a routing bug.
* **`channel.Endpoint.InjectInbound` silently drops a packet when the endpoint
  is not attached.** A unit test that does not attach a dispatcher therefore
  "loses" packets that the shim delivered correctly.
* **`channel.Endpoint.Read` does not block.** The shim reads through
  `ReadContext`; with the plain `Read` wg sees an empty read, decides the
  device is gone and closes it.
* **Route lookup in this netstack is first-match in table order**, not
  longest-prefix, so the guest subnet has to be installed before the tunnel
  routes, and the default route last.
* **A pinned socket's NIC is honoured**, but the source address has to come from
  that interface: bind the wildcard address on the NIC, never the destination
  address, which is not a local address and fails the route lookup.
* **Four-byte and sixteen-byte IPv4 addresses are not equal.** An address from
  the kernel is four bytes and one from `net.ResolveUDPAddr` is sixteen;
  comparing `netip.AddrPort`s, or `IP` slices with `==`, throws away every
  reply a relay is waiting for. Use `net.IP.Equal`.
* **wg's `IpcGet` uses `last_handshake_time_sec`**, not `latest_…`, and its
  dump includes the private key: parse the fields you need and never log the
  dump.
* **`stack.Options.HandleLocal` must stay false** while the NIC is promiscuous.
  HandleLocal means "a packet whose source address is one of mine is for me",
  and a promiscuous NIC considers every address it has seen to be one of
  theirs — with both on, the gateway drops all guest traffic as
  `ip.InvalidSourceAddressesReceived`.
* **`tcpip.LinkAddress` holds raw bytes**, not the `52:54:…` text. Passing
  `mac.String()` puts ASCII into the ethernet header and ARP "works" only by
  accident. Use `ethlink.LinkAddr(hwaddr)`.
* **A codec that only ever talks to itself proves nothing.** DHCP tests that
  encode with our own `Marshal` and decode with our own `Parse` agree with each
  other whatever the bytes are, which is how the magic cookie sat as the
  transposed `0x63824536` instead of the RFC's `0x63825363` with every test
  green: our requests were malformed to the client, and every answer we sent was
  one no client would open, so a guest running dhclient saw no DHCP at all. Wire
  formats are pinned with hand-written bytes instead — `wireDISCOVER` in
  `internal/dhcp`, `handAssembledDiscover` in `internal/engine`, `query` and
  `oneLabelQuery` in `internal/dns` — the reply's own cookie bytes are checked,
  and every reply is decoded by somebody else's implementation:
  `internal/dns/interop_test.go` reads them with `x/net/dns/dnsmessage`, and
  `internal/dhcp/interop_test.go` runs the whole exchange against
  `insomniacslk/dhcp`, which stays a test-only import. One direction of the DNS
  check has gone: the gateway now reads queries with `dnsmessage` too, so a
  query written by `dnsmessage` no longer tests anything, and the queries that
  matter there are the ones assembled from bytes. They found a transposed MTU
  option and a renewal time taken from the rebinding setting, neither of which
  anything else in the tree noticed. The ethernet, IPv4, TCP, UDP
  and ICMP headers are read with the netstack's own `header` types, so those
  cannot drift from what the stack accepts.
* **Deliver with the real ethertype.** The ethernet wrapper ignores it, but
  the sniffer sits above it and logs "unknown network protocol: 0" otherwise.
* **The sniffer goes above the ethernet wrapper**, never below: it expects the
  link header to have been parsed off the packet.
* A malformed frame must not kill the session: `ethlink.Run` counts a bad frame
  length and keeps reading.
* **Do not queue egress frames to dodge a guest that is not reading.**
  A bounded ring inside `ethlink`, dropping what does not fit, looks like the
  tidy answer and is not: the stack is told the frame left, so it never aborts
  the endpoint whose FIN or data went into the ring. After a guest reboot with
  relays still open, the mapped address and port stay reserved for about a
  retransmit timeout, the new session's relay fails to bind it (`port is in use`)
  and the guest is handed a reset. Write on the goroutine that produced the
  packet and
  bound the *wait* instead, which is what `frame.Stream` does, so the failure
  reaches the stack on the same call.
* Defaults that mean "unset": `mtu = 0`, `pool_size = 0` and `lease_time = ""`
  are how a file leaves a number at its default, because a plain TOML value
  cannot tell an omitted key from a zero. The switches that are on by default
  (`dhcp.enabled`, `gateway.internet`) are defaulted by decoding the file over
  `config.DefaultFile`, so they only have to be written down to be turned off.
* Do not reach for wg's own `tun/netstack` package to join the two stacks: it
  imports `pkg/bufferv2`, which this pinned netstack no longer has.

## Limitations

This is a proof of concept.

* IPv4 only, on both sides: no IPv6 to the guest, no NDP, no router
  advertisement, and the tunnel's IPv6 addresses and `AllowedIPs` are ignored.
* One peer per tunnel. Site-to-site setups and multi-hop routing are out.
* The tunnel is built once, at startup: no roaming between networks, no
  re-resolving a peer's name, no key rotation without a restart, no
  `PersistentKeepalive`-driven rekeying surprises beyond what wg-go itself does.
* ICMP is echo, and nothing else. `ping` works: the gateway answers its own
  addresses and relays the rest through the tunnel. What it does not do is
  generate ICMP error messages, so a refused destination is silence rather than
  `host unreachable`; answer a ping sent to a broadcast or multicast address
  (there is no single address to answer from); reassemble fragments, so a ping
  split across fragments is refused and counted rather than answered, and one
  larger than the link MTU does not arrive at all; or answer an echo answer the
  guest is forwarding to somebody else, or one whose checksums do not add up.
  Answers are crafted per request rather than rate limited, so their cost is
  bounded by the 128 pings in flight.
* An inbound `[[forward]]` needs the guest to be configured: the gateway
  resolves the guest's address with ARP before it can dial it, so a host
  connection that arrives before the guest has an address is refused. passt
  buffers those connections instead.
* A UDP `[[forward]]` connects one host peer at a time, like QEMU's `hostfwd`:
  datagrams from a second peer take the flow over, so the first one's answers
  start arriving at the second. Per-peer state for a forward the operator named
  is not something the POC holds.
* No checksum offload on transmit, so every segment is computed in software.
  Inbound sums are trusted, because the endpoint tells the stack the link
  validates them; the echo frames answered here are checked anyway, since for
  those this gateway is the receiver.
* Two seconds is how long one frame may wait for a guest that has stopped taking
  frames, and that number is not configuration. A guest whose device is slow
  rather than stuck is disconnected if it cannot take a frame inside it.
* On-demand relays are per (address, port) in a fixed table of 2048 slots. An
  idle one is given back to the next relay that needs room, and a disconnect
  clears the table, but the cap is hard: a guest that sprays SYNs at 2048
  distinct live ports refuses service to itself. A UDP relay opens at most 32 datagram
  paths, and the gateway holds at most 1024 across all of them, reported as
  `paths` in the stats line; that budget is what stops relays times paths
  becoming tens of thousands of host sockets. Pings are capped at 128 in
  flight and one `[[forward]]` bridges at most 64 host connections; both
  numbers are fixed, not configuration.
* The gateway's own resolver asks one upstream query at a time, so a guest
  that fires a hundred lookups at once queues them. The relay is correct, not
  fast.
* The DHCP server checks a requested address against the pool, not against the
  gateway and resolver addresses, so keep `network.guest_ip` above those: a
  pool that covers them lets a guest be handed an address we also answer for.
  The lease table is capped at the pool's size and a DISCOVER with nothing to
  offer is left unanswered, so a guest inventing hardware addresses cannot grow
  it; it can still fill the pool, which locks other guests out until the leases
  expire. `network.guest_mac` pins one address and is worth setting whenever the
  guest is not the only thing on the link.
* A tunnel whose `AllowedIPs` cover the guest's subnet work, and the gateway
  warns: the subnet keeps its own route to the QEMU link, and a guest is
  refused any destination inside its own segment rather than being handed a
  relay the peer could answer for. A VPN that expects to *serve* that subnet
  is a different setup.
* No save/restore, no multiqueue, no GRO/TSO to the guest, no statistics socket,
  and no SMB/NCSI protocols that passt implements.
