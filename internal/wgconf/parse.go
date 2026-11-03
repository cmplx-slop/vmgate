package wgconf

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// Parse reads wg-quick syntax. Sections are [Interface] and [Peer], keys are
// case-insensitive, a value list is comma separated, and # or ; start a
// comment. What comes back has been validated.
func Parse(name string, r io.Reader) (*Config, error) {
	p := &parser{c: &Config{MTU: DefaultMTU}}

	sc := bufio.NewScanner(r)
	for no := 1; sc.Scan(); no++ {
		line := stripComment(strings.TrimSpace(sc.Text()))
		if line == "" {
			continue
		}
		if err := p.line(name, no, line); err != nil {
			return nil, err
		}
	}
	p.closePeer()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if err := p.c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	return p.c, nil
}

// parser is the file being read: what has been collected so far, and which
// section the lines are being read under. Its methods take a bare line and say
// what went wrong without the position, which Parse adds, so that the wording
// of a complaint about PrivateKey does not depend on where it was written.
type parser struct {
	c       *Config
	cur     *Peer
	section string
}

// line reads one non-blank line, which is either a section header or a
// key = value setting under the current section.
func (p *parser) line(name string, no int, line string) error {
	if strings.HasPrefix(line, "[") {
		if !strings.HasSuffix(line, "]") {
			return fmt.Errorf("%s:%d: malformed section %q", name, no, line)
		}
		p.closePeer()
		p.section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
		switch p.section {
		case "interface":
		case "peer":
			p.cur = &Peer{}
		default:
			return fmt.Errorf("%s:%d: unknown section %q", name, no, line)
		}
		return nil
	}
	if p.section == "" {
		return fmt.Errorf("%s:%d: setting before any [Interface] or [Peer]", name, no)
	}

	key, val, ok := strings.Cut(line, "=")
	if !ok {
		return fmt.Errorf("%s:%d: %q is not a key = value line", name, no, line)
	}
	key = strings.ToLower(strings.TrimSpace(key))
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("%s:%d: %s has no value", name, no, key)
	}

	var err error
	if p.section == "interface" {
		err = p.setInterface(key, val)
	} else {
		err = p.setPeer(key, val)
	}
	if err != nil {
		return fmt.Errorf("%s:%d: %v", name, no, err)
	}
	return nil
}

func (p *parser) setInterface(key, val string) error {
	c := p.c
	switch key {
	case "privatekey":
		if c.PrivateKey != nil {
			return errors.New("private key given twice")
		}
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PrivateKey: %v", err)
		}
		c.PrivateKey = k
	case "address", "addresses":
		for _, entry := range splitList(val) {
			pfx, err := parsePrefix(entry)
			if err != nil {
				return err
			}
			if err := checkAddress(pfx); err != nil {
				return fmt.Errorf("address %q %v", entry, err)
			}
			c.Addresses = append(c.Addresses, pfx)
		}
	case "dns":
		for _, entry := range splitList(val) {
			ip := net.ParseIP(entry)
			if ip == nil {
				return fmt.Errorf("dns %q is not an IP address (the gateway has no resolver to ask before the tunnel is up)", entry)
			}
			if ip.To4() == nil {
				// A wg-quick file often names both families. This gateway
				// speaks IPv4 to the guest and over the tunnel, so an
				// address from the other one has nowhere to go; skipping it
				// beats refusing a file a VPN provided.
				continue
			}
			c.DNS = append(c.DNS, ip)
		}
	case "listenport":
		port, err := strconv.ParseUint(val, 10, 16)
		// 0 is how a file says "let the host choose", which is what leaving
		// the key out means; both end up with no listen_port for wg.
		if err != nil || port > 65535 {
			return fmt.Errorf("listen_port %q is not a port", val)
		}
		c.ListenPort = int(port)
	case "mtu":
		mtu, err := strconv.Atoi(val)
		if err != nil || mtu < minTunnelMTU || mtu > maxTunnelMTU {
			return fmt.Errorf("mtu %q is out of range (%d-%d)", val, minTunnelMTU, maxTunnelMTU)
		}
		c.MTU = mtu
	case "table", "fwmark", "preup", "predown", "predisconnect", "postup", "postdown", "savedns", "saveconfig":
		// wg-quick's instructions for the kernel side. There is no kernel
		// side here, so these are accepted and have no effect: a file that
		// works with wg-quick keeps working.
	default:
		return fmt.Errorf("unknown interface setting %q", key)
	}
	return nil
}

func (p *parser) setPeer(key, val string) error {
	cur := p.cur
	switch key {
	case "publickey":
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PublicKey: %v", err)
		}
		cur.PublicKey = k
	case "presharedkey":
		k, err := parseKey(val)
		if err != nil {
			return fmt.Errorf("PresharedKey: %v", err)
		}
		cur.PreSharedKey = k
	case "endpoint":
		if _, _, err := net.SplitHostPort(val); err != nil {
			return fmt.Errorf("endpoint %q is not host:port", val)
		}
		cur.Endpoint = val
	case "allowedips":
		for _, entry := range splitList(val) {
			pfx, err := parseRoute(entry)
			if err != nil {
				return err
			}
			cur.AllowedIPs = append(cur.AllowedIPs, pfx)
		}
	case "persistentkeepalive":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 120 {
			return fmt.Errorf("persistent_keepalive %q is out of range (0-120)", val)
		}
		cur.Keepalive = n
	default:
		return fmt.Errorf("unknown peer setting %q", key)
	}
	return nil
}

// closePeer finishes the [Peer] being read, if any, so the next section starts
// a fresh one.
func (p *parser) closePeer() {
	if p.cur != nil {
		p.c.Peers = append(p.c.Peers, *p.cur)
		p.cur = nil
	}
}
