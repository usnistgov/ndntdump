package ndntdump_test

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/usnistgov/ndntdump"
	"go4.org/netipx"
)

func TestAnonymizer(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	keepIPs, e := ndntdump.ParseIPSet([]string{
		"10.0.4.32/28",
		"10.0.10.0/23",
		"fc44:966b:ce32:f10a::/64",
	})
	require.NoError(e)
	var expectKeepIPsBuilder netipx.IPSetBuilder
	expectKeepIPsBuilder.AddPrefix(netip.MustParsePrefix("10.0.4.0/24"))
	expectKeepIPsBuilder.AddPrefix(netip.MustParsePrefix("10.0.10.0/23"))
	expectKeepIPsBuilder.AddPrefix(netip.MustParsePrefix("fc44:966b:ce32::/48"))
	expectKeepIPs, _ := expectKeepIPsBuilder.IPSet()
	assert.True(keepIPs.Equal(expectKeepIPs))

	secret := [ndntdump.AnonymizerSecretLen]byte(bytes.Repeat([]byte{0x01}, ndntdump.AnonymizerSecretLen))
	anon := ndntdump.NewAnonymizer(keepIPs, false, &secret)

	for _, ipPair := range [][2]string{
		{"10.0.4.2", "10.0.4.2"},
		{"10.0.5.2", "10.0.5.3"},
		{"10.0.11.2", "10.0.11.2"},
		{"10.0.12.2", "10.0.12.3"},
		{"fc44:966b:ce32:52c6:74cd:f818:963b:202b", "fc44:966b:ce32:52c6:74cd:f818:963b:202b"},
		{"fc9b:fd7b:5f42:47d0:78c0:fcb6:85c7:84a3", "fc9b:fd7b:5f42:46d1:79c1:fdb7:84c6:85a2"},
	} {
		ip := net.ParseIP(ipPair[0])
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}
		anon.AnonymizeIP(ip)
		assert.Equal(ipPair[1], ip.String())
	}

	badIP := net.IP{0xF0, 0xF1, 0xF2, 0xF3, 0xF4} // neither IPv4 nor IPv6
	anon.AnonymizeIP(badIP)
	assert.Equal(net.IP{0xF0, 0xF1, 0xF2, 0xF3, 0xF4}, badIP) // unchanged

	hwaddr, e := net.ParseMAC("02:bf:8f:44:91:da")
	require.NoError(e)
	anon.AnonymizeMAC(hwaddr)
	assert.Equal("02:bf:8f:45:90:db", hwaddr.String())
}
