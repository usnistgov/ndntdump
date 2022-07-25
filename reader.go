package ndn6dump

import (
	"bytes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/usnistgov/ndn-dpdk/ndn"
	"github.com/usnistgov/ndn-dpdk/ndn/ndnlayer"
)

var lotsOfZeros [65536]byte

func saveFlowAddrs[A ~[]byte](flow []byte, src, dst A) []byte {
	if bytes.Compare(src, dst) < 0 {
		flow = append(flow, src...)
		flow = append(flow, dst...)
	} else {
		flow = append(flow, dst...)
		flow = append(flow, src...)
	}
	return flow
}

func saveFlowPorts[N ~uint16](flow []byte, proto uint8, src, dst N) []byte {
	if src > dst {
		src, dst = dst, src
	}
	return append(flow, proto, uint8(src>>8), uint8(src), uint8(dst>>8), uint8(dst))
}

// Reader reads NDN packets from ZeroCopyPacketDataSource.
type Reader struct {
	src gopacket.ZeroCopyPacketDataSource
	ipa *IPAnonymizer

	dlp     *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	udp     layers.UDP
	tlv     ndnlayer.TLV
	ndn     ndnlayer.NDN
}

// Read reads an NDN packet.
//
// []byte fields within returned structure are valid until next call to this function.
func (r *Reader) Read() (rec Record, e error) {
RETRY:
	rec = Record{}
	if rec.Wire, rec.CaptureInfo, e = r.src.ZeroCopyReadPacketData(); e != nil {
		return
	}

	if e = r.dlp.DecodeLayers(rec.Wire, &r.decoded); e != nil {
		goto RETRY
	}

	ethOnly := true
	var pkt *ndn.Packet
	for _, layerType := range r.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
		case layers.LayerTypeIPv4:
			r.ipa.Anonymize(r.ip4.SrcIP)
			r.ipa.Anonymize(r.ip4.DstIP)
			ethOnly = false
			rec.Flow = saveFlowAddrs(rec.Flow, r.ip4.SrcIP, r.ip4.DstIP)
		case layers.LayerTypeIPv6:
			r.ipa.Anonymize(r.ip6.SrcIP)
			r.ipa.Anonymize(r.ip6.DstIP)
			ethOnly = false
			rec.Flow = saveFlowAddrs(rec.Flow, r.ip6.SrcIP, r.ip6.DstIP)
		case layers.LayerTypeUDP:
			rec.Flow = saveFlowPorts(rec.Flow, uint8(layers.IPProtocolUDP), r.udp.SrcPort, r.udp.DstPort)
		case ndnlayer.LayerTypeTLV:
			rec.Size = len(r.tlv.LayerContents())
		case ndnlayer.LayerTypeNDN:
			pkt = r.ndn.Packet
		}
	}

	switch {
	case pkt == nil:
		goto RETRY
	case pkt.Fragment != nil:
		rec.Type = PktTypeFragment
	case pkt.Interest != nil:
		rec.Type = PktTypeInterest
		rec.Name = pkt.Interest.Name
		rec.CanBePrefix = pkt.Interest.CanBePrefix
		rec.MustBeFresh = pkt.Interest.MustBeFresh
		copy(pkt.Interest.AppParameters, lotsOfZeros[:])
		copy(pkt.Interest.SigValue, lotsOfZeros[:])
	case pkt.Data != nil:
		rec.Type = PktTypeData
		rec.Name = pkt.Data.Name
		rec.DataDigest = pkt.Data.ComputeDigest()
		rec.FinalBlock = pkt.Data.IsFinalBlock()
		copy(pkt.Data.Content, lotsOfZeros[:])
		copy(pkt.Data.SigValue, lotsOfZeros[:])
	case pkt.Nack != nil:
		rec.Type = PktTypeNack
		rec.Name = pkt.Nack.Name()
	}

	rec.Timestamp = rec.CaptureInfo.Timestamp.UnixNano()
	if ethOnly {
		rec.Flow = saveFlowAddrs(rec.Flow, r.eth.SrcMAC, r.eth.DstMAC)
	}

	rec.CaptureInfo.InterfaceIndex = 0
	rec.CaptureInfo.AncillaryData = nil
	return
}

// NewReader creates Reader.
func NewReader(src gopacket.ZeroCopyPacketDataSource, ipa *IPAnonymizer) (r *Reader) {
	r = &Reader{
		src: src,
		ipa: ipa,
	}

	r.dlp = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &r.eth, &r.ip4, &r.ip6, &r.udp, &r.tlv, &r.ndn)
	r.dlp.IgnoreUnsupported = true
	return r
}
