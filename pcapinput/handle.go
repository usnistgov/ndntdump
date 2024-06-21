// Package pcapinput opens GoPacket input handle.
package pcapinput

import (
	"errors"
	"io"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
)

// Handle represents a pcap input handle.
type Handle interface {
	gopacket.ZeroCopyPacketDataSource
	io.Closer
	Name() string
	IsLocal(mac net.HardwareAddr) bool
}

// Open creates a pcap input handle.
//
//	ifname: network interface name.
//	filename: input filename.
//	local: local MAC address.
func Open(ifname, filename, local string) (handle Handle, e error) {
	if (ifname == "") == (filename == "") {
		return nil, errors.New("exactly one of ifname and filename+local should be specified")
	}

	if ifname != "" {
		hdl := &netifHandle{ifname: ifname}
		if e = hdl.open(); e != nil {
			return nil, e
		}
		return hdl, nil
	}

	localMAC, e := net.ParseMAC(local)
	if e != nil || !macaddr.IsUnicast(localMAC) {
		return nil, errors.New("invalid local MAC address")
	}
	hdl := &fileHandle{local: localMAC}
	if e = hdl.open(filename); e != nil {
		hdl.Close()
		return nil, e
	}
	return hdl, nil
}
