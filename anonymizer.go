package ndntdump

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net"

	"inet.af/netaddr"
)

// Anonymizer anonymizes IP addresses and MAC addresses.
// Initial 24 bits of IPv4 address, 48 bits of IPv6 address, and 48 bits of MAC address are kept.
// Later bits are XOR'ed with a secret key.
type Anonymizer struct {
	keepIPs *netaddr.IPSet
	keepMAC bool
	secret  [14]byte
}

// AnonymizeIP anonymizes an IP address.
func (anon *Anonymizer) AnonymizeIP(ip net.IP) {
	if nip, ok := netaddr.FromStdIP(ip); !ok || anon.keepIPs.Contains(nip) {
		return
	}

	switch len(ip) {
	case 4:
		ip[3] ^= anon.secret[10]
	case 16:
		subtle.XORBytes(ip[6:], ip[6:], anon.secret[0:10])
	}
}

// AnonymizeMAC anonymizes a MAC address.
func (anon *Anonymizer) AnonymizeMAC(mac net.HardwareAddr) {
	if !anon.keepMAC && len(mac) == 6 {
		subtle.XORBytes(mac[3:], mac[3:], anon.secret[11:14])
	}
}

// NewAnonymizer creates Anonymizer.
func NewAnonymizer(keepIPs *netaddr.IPSet, keepMAC bool) (anon *Anonymizer) {
	anon = &Anonymizer{
		keepIPs: keepIPs,
		keepMAC: keepMAC,
	}
	rand.Read(anon.secret[:])
	return
}

// ParseIPSet parses CIDR strings into IPSet.
// IPv4 prefixes are shortened to /24.
// IPv6 prefixes are shortened to /48.
func ParseIPSet(input []string) (*netaddr.IPSet, error) {
	var b netaddr.IPSetBuilder
	for i, prefix := range input {
		p, e := netaddr.ParseIPPrefix(prefix)
		if e != nil {
			return nil, fmt.Errorf("%d %w", i, e)
		}

		ip, bits := p.IP(), p.Bits()
		switch {
		case ip.Is4() && bits > 24:
			p = netaddr.IPPrefixFrom(ip, 24)
		case ip.Is6() && bits > 48:
			p = netaddr.IPPrefixFrom(ip, 48)
		}

		b.AddPrefix(p)
	}
	return b.IPSet()
}
