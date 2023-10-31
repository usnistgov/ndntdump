package ndntdump

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net"
	"net/netip"

	"go4.org/netipx"
)

// AnonymizerSecretLen is the length of secret key inside Anonymizer.
const AnonymizerSecretLen = 14

// Anonymizer anonymizes IP addresses and MAC addresses.
// IPv4 address keeps its leading 24 bits; IPv6 address keeps its leading 48 bits; MAC address keeps its leading 24 bits.
// Lower bits are XOR'ed with a random value.
type Anonymizer struct {
	keepIPs *netipx.IPSet
	keepMAC bool
	secret  [AnonymizerSecretLen]byte
}

// AnonymizeIP anonymizes an IP address.
func (anon *Anonymizer) AnonymizeIP(ip net.IP) {
	if nip, ok := netip.AddrFromSlice(ip); !ok || anon.keepIPs.Contains(nip) {
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
func NewAnonymizer(keepIPs *netipx.IPSet, keepMAC bool, secret *[AnonymizerSecretLen]byte) (anon *Anonymizer) {
	anon = &Anonymizer{
		keepIPs: keepIPs,
		keepMAC: keepMAC,
	}
	if secret == nil {
		rand.Read(anon.secret[:])
	} else {
		anon.secret = *secret
	}
	return
}

// ParseIPSet parses CIDR strings into IPSet.
// IPv4 prefixes are shortened to /24.
// IPv6 prefixes are shortened to /48.
func ParseIPSet(input []string) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder
	for i, prefix := range input {
		p, e := netip.ParsePrefix(prefix)
		if e != nil {
			return nil, fmt.Errorf("%d %w", i, e)
		}

		ip, bits := p.Addr(), p.Bits()
		switch {
		case ip.Is4() && bits > 24:
			p = netip.PrefixFrom(ip, 24)
		case ip.Is6() && bits > 48:
			p = netip.PrefixFrom(ip, 48)
		}

		b.AddPrefix(p)
	}
	return b.IPSet()
}
