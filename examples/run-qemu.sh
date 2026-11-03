#!/bin/sh
# Start vmgate and a QEMU guest joined by a unix socket.
#
# vmgate does not need any privilege: it is a plain user process that talks
# ethernet frames to QEMU over a socket. QEMU can be the one that dials (the
# default here, vmgate listens) or the one that listens (server=on, then
# vmgate uses -connect).
#
# Everything the guest reaches beyond the gateway goes through a WireGuard
# tunnel, also inside this process: no wg, no wg-quick, no kernel interface. The
# tunnel is read from a wg-quick file, which is why VPN_CONF below is required.
# The forwards and services below keep using the host's own sockets.
#
# The configuration itself is a TOML file. This script writes a short one from
# the environment so the knobs below keep working; for anything real, copy
# examples/vmgate.toml and edit that.
#
# Environment:
#   GUEST      disk image to boot            (default: ./guest.qcow2)
#   KERNEL     kernel to boot directly       (default: empty, uses the image)
#   SOCKET     socket joining the two        (default: $XDG_RUNTIME_DIR or
#                                            /tmp/vmgate-<uid>/vmgate.sock)
#   VPN_CONF   wg-quick file for the tunnel  (default: examples/vpn.conf, whose
#                                            keys are placeholders, so point it
#                                            at a real tunnel to get anywhere)
#   SSH_PORT   host port forwarded to sshd   (default: 2222)
#   HTTP_PORT  guest 80 -> this host port    (default: 8080)
#   LEGACY=1   use -netdev socket (older QEMU, same framing)

set -eu

# A socket anyone can reach is a socket anyone can answer as the guest, so the
# default lives in the per-user runtime directory.
runtime=${XDG_RUNTIME_DIR:-/tmp/vmgate-$(id -u)}

GUEST=${GUEST:-./guest.qcow2}
KERNEL=${KERNEL:-}
SOCKET=${SOCKET:-$runtime/vmgate.sock}
VPN_CONF=${VPN_CONF:-}
SSH_PORT=${SSH_PORT:-2222}
HTTP_PORT=${HTTP_PORT:-8080}

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname -- "$here")
binary="$root/vmgate"

die() {
	printf '%s\n' "$1" >&2
	exit 1
}

# No tunnel, no way out for a guest, so the gateway would refuse to start
# anyway: say what is missing here, where the environment is obvious.
if [ -z "$VPN_CONF" ]; then
	VPN_CONF=$here/vpn.conf
	printf 'using the sample tunnel %s\n' "$VPN_CONF"
	printf 'its keys are placeholders, so the guest will have no route out until\n'
	printf 'VPN_CONF names a wg-quick file for a VPN you can actually reach\n'
fi
if [ ! -r "$VPN_CONF" ]; then
	die "VPN_CONF is not a readable wg-quick file: $VPN_CONF"
fi

# These values are written into TOML strings below, so a quote or a newline in
# one is a configuration injection rather than a value: it could add a
# [[forward]] nobody asked for, or point [vpn] at a different tunnel file.
# Reject anything odd instead, paths included: a tunnel file with a space in
# its name is a thing to rename.
case $SSH_PORT in ('' | *[!0-9]*) die "SSH_PORT must be a number: $SSH_PORT" ;; esac
case $HTTP_PORT in ('' | *[!0-9]*) die "HTTP_PORT must be a number: $HTTP_PORT" ;; esac
for name in SOCKET VPN_CONF; do
	eval value=\$$name
	if [ "$(printf '%s\n' "$value" | wc -l)" -ne 1 ] || printf '%s' "$value" | grep -q '["\\ ]'; then
		die "$name must not contain quotes, backslashes, spaces or newlines"
	fi
done

if [ ! -x "$binary" ]; then
	printf 'building vmgate\n'
	(cd "$root" && go build -o vmgate ./cmd/vmgate)
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
	printf 'qemu-system-x86_64 not found; the command line below is what this script runs\n'
fi

rm -f "$SOCKET"

conf=$(mktemp "${TMPDIR:-/tmp}/vmgate.XXXXXX")
cat >"$conf" <<EOF
[link]
listen = "unix:$SOCKET"

[vpn]
conf = "$VPN_CONF"

[dns]
map_hosts = ["host.local"]

[[forward]]            # host ssh -> guest sshd
host_port = $SSH_PORT
guest_port = 22

[[service]]            # guest gateway:80 -> host :$HTTP_PORT
guest_port = 80
host_port = $HTTP_PORT

[log]
verbosity = 1
EOF

"$binary" -config "$conf" &
gw=$!
trap 'kill "$gw" 2>/dev/null || true; rm -f "$SOCKET" "$conf"' EXIT INT TERM

# Wait for the socket to appear so QEMU never races with it.
i=0
while [ ! -S "$SOCKET" ]; do
	i=$((i + 1))
	if [ "$i" -gt 100 ]; then
		printf 'vmgate did not create %s\n' "$SOCKET" >&2
		exit 1
	fi
	sleep 0.1
done

if [ -n "$KERNEL" ]; then
	set -- -kernel "$KERNEL" -append "console=ttyS0 ip=dhcp"
else
	set -- -drive file="$GUEST",if=virtio,format=qcow2
fi

if [ -n "${LEGACY:-}" ]; then
	# -netdev socket speaks the same length prefixed framing, so nothing else
	# about the setup changes.
	# shellcheck disable=SC2086
	qemu-system-x86_64 \
		-machine q35 -m 2048 -nographic \
		"$@" \
		-netdev socket,id=n0,connect=$SOCKET \
		-device virtio-net-pci,netdev=n0
else
	# shellcheck disable=SC2086
	qemu-system-x86_64 \
		-machine q35 -m 2048 -nographic \
		"$@" \
		-netdev stream,id=n0,addr.type=unix,addr.path=$SOCKET \
		-device virtio-net-pci,netdev=n0
fi

# Once the guest is up, these are the checks that prove the plumbing works:
#
#   guest# ip a            # 10.0.2.15/24, gateway 10.0.2.2, and the tunnel's
#                          # MTU rather than 1500 when the tunnel is smaller
#   guest# getent hosts host.local # the gateway answers its own names; anything
#                          # else goes through the tunnel, and fails until the
#                          # peer answers
#   guest# wget -qO- http://1.1.1.1/ | head -1   # out through the tunnel
#   guest# ping -c2 10.0.2.2           # the gateway answers its own addresses
#   guest# ping -c2 1.1.1.1            # relayed out through the tunnel
#   guest# curl -s http://10.0.2.2/     # [[service]] out to the host's :8080
#   host$  ssh -p $SSH_PORT 127.0.0.1   # [[forward]] into the guest
#
# Ping works, and it is the quickest way to see what the tunnel will carry: the
# gateway answers a ping to an address it owns (the gateway itself, the DNS
# address, the tunnel's), and relays a ping to anything else through the tunnel,
# where the peer's AllowedIPs decide whether the request can leave at all. No
# reply means the tunnel does not carry that address or the egress policy refuses
# it; `icmp_answered` and `icmp_relayed` in the stats line say which pings the
# gateway answered itself and which it sent on.
#
# The stats line the gateway prints every so often reports the tunnel:
# vpn_endpoint, vpn_handshake, vpn_tx, vpn_rx, and the counters for what it
# refused and why - vpn_refused for a packet that is not a packet, vpn_misaimed
# for one aimed at an address the tunnel does not carry. With the sample
# vpn.conf the handshake never completes and every guest destination past the
# gateway is refused, which is the tunnel working as designed rather than a
# guest that is broken: point VPN_CONF at a VPN that answers to see traffic
# move.
