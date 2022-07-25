package ndn6dump

import (
	"crypto/rand"
	"fmt"
	"net"

	"inet.af/netaddr"
)

// IPAnonymizer anonymizes IP addresses.
// Initial 24 bits of IPv4 address and 48 bits of IPv6 address are kept; later bits are XOR'ed with a secret key.
type IPAnonymizer struct {
	keep   *netaddr.IPSet
	secret [11]byte
}

// Anonymize anonymizes one IP address.
func (ipa *IPAnonymizer) Anonymize(ip net.IP) {
	if nip, ok := netaddr.FromStdIP(ip); !ok || ipa.keep.Contains(nip) {
		return
	}

	switch len(ip) {
	case 4:
		ip[3] ^= ipa.secret[10]
	case 16:
		for i := 0; i < 10; i++ {
			ip[6+i] ^= ipa.secret[i]
		}
	}
}

// NewIPAnonymizer creates IPAnonymizer.
func NewIPAnonymizer(keep *netaddr.IPSet) (ipa *IPAnonymizer) {
	ipa = &IPAnonymizer{
		keep: keep,
	}
	rand.Read(ipa.secret[:])
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
