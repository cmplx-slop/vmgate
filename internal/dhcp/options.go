package dhcp

import (
	"encoding/binary"
	"net"
)

// Option is one TLV.
type Option struct {
	Code  byte
	Value []byte
}

// Options is an ordered option list.
type Options []Option

// Get returns the first value for code.
func (o Options) Get(code byte) ([]byte, bool) {
	for _, opt := range o {
		if opt.Code == code {
			return opt.Value, true
		}
	}
	return nil, false
}

// IP returns the first IPv4 address of option code.
func (o Options) IP(code byte) net.IP {
	v, ok := o.Get(code)
	if !ok || len(v) < 4 {
		return nil
	}
	return net.IP(v[:4])
}

// IPs returns all IPv4 addresses of option code.
func (o Options) IPs(code byte) []net.IP {
	v, ok := o.Get(code)
	if !ok {
		return nil
	}
	var out []net.IP
	for i := 0; i+4 <= len(v); i += 4 {
		out = append(out, net.IP(v[i:i+4]))
	}
	return out
}

// U32 returns a big endian 32 bit option value.
func (o Options) U32(code byte) (uint32, bool) {
	v, ok := o.Get(code)
	if !ok || len(v) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

// Set replaces (or appends) the value of code, preserving order.
func (o *Options) Set(code byte, value []byte) {
	for i, opt := range *o {
		if opt.Code == code {
			(*o)[i].Value = value
			return
		}
	}
	*o = append(*o, Option{Code: code, Value: value})
}

func ip4(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return []byte{0, 0, 0, 0}
}

// encodeIPs/encodeUint32 are helpers for building option values.
func encodeIPs(ips ...net.IP) []byte {
	var out []byte
	for _, ip := range ips {
		out = append(out, ip4(ip)...)
	}
	return out
}

// encodeUint32 encodes a big endian 32 bit option value.
func encodeUint32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
