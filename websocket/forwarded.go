package websocket

import (
	"bytes"
	"net/netip"
	"regexp"
)

var reXForwardedFor = regexp.MustCompile("(?im)\r\nx-forwarded-for:(.*)\r\n")
var lotsOfSpaces = bytes.Repeat([]byte(" "), 256)

// AnonymizeXForwardedFor recognizes an UPGRADE request and anonymizes IP address enclosed in X-Forwarded-For header.
// Initial 24 bits of IPv4 address and 48 bits of IPv6 address are kept; later bits are set to zeros.
func AnonymizeXForwardedFor(p []byte) {
	if !bytes.HasPrefix(p, []byte("GET ")) || !bytes.HasSuffix(p, []byte("\r\n\r\n")) {
		return
	}

	matches := reXForwardedFor.FindAllSubmatchIndex(p, -1)
	for _, match := range matches {
		room := p[match[2]:match[3]]
		ip, e := netip.ParseAddr(string(bytes.TrimSpace(room)))
		if e != nil {
			continue
		}
		switch {
		case ip.Is4():
			ip = netip.PrefixFrom(ip, 24).Masked().Addr()
		case ip.Is6():
			ip = netip.PrefixFrom(ip, 48).Masked().Addr()
		default:
			continue
		}
		repl := []byte(ip.String())

		// masked address is expected to be no longer than original
		headroom := len(room) - len(repl)
		copy(room[:headroom], lotsOfSpaces)
		copy(room[headroom:], repl)
	}
}
