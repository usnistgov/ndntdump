package ndn6dump

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
	"github.com/usnistgov/ndn-dpdk/ndn"
	"github.com/usnistgov/ndn-dpdk/ndn/an"
	"github.com/usnistgov/ndn-dpdk/ndn/ndnlayer"
	"github.com/usnistgov/ndn-dpdk/ndn/tlv"
)

var lotsOfZeros [65536]byte

func zeroizeInterestPayload(interest *ndn.Interest) {
	copy(interest.AppParameters, lotsOfZeros[:])
	copy(interest.SigValue, lotsOfZeros[:])
}

func zeroizeDataPayload(data *ndn.Data) {
	copy(data.Content, lotsOfZeros[:])
	copy(data.SigValue, lotsOfZeros[:])
}

func saveFlowAddrs[A ~[]byte](flow []byte, dir Direction, src, dst A) []byte {
	if dir == DirectionRX {
		src, dst = dst, src
	}
	flow = append(flow, src...)
	flow = append(flow, dst...)
	return flow
}

func saveFlowPorts[N ~uint16](flow []byte, dir Direction, proto uint8, src, dst N) []byte {
	if dir == DirectionRX {
		src, dst = dst, src
	}
	return append(flow, proto, uint8(src>>8), uint8(src), uint8(dst>>8), uint8(dst))
}

// Reader reads NDN packets from ZeroCopyPacketDataSource.
type Reader struct {
	src   gopacket.ZeroCopyPacketDataSource
	local net.HardwareAddr
	ipa   *IPAnonymizer

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
	var dir Direction
	var pkt *ndn.Packet
	for _, layerType := range r.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			switch {
			case macaddr.Equal(r.local, r.eth.SrcMAC):
				dir = DirectionTX
			case macaddr.Equal(r.local, r.eth.DstMAC):
				dir = DirectionRX
			default:
				goto RETRY
			}
		case layers.LayerTypeIPv4:
			ethOnly = false
			r.ipa.Anonymize(r.ip4.SrcIP)
			r.ipa.Anonymize(r.ip4.DstIP)
			rec.Flow = saveFlowAddrs(rec.Flow, dir, r.ip4.SrcIP, r.ip4.DstIP)
		case layers.LayerTypeIPv6:
			ethOnly = false
			r.ipa.Anonymize(r.ip6.SrcIP)
			r.ipa.Anonymize(r.ip6.DstIP)
			rec.Flow = saveFlowAddrs(rec.Flow, dir, r.ip6.SrcIP, r.ip6.DstIP)
		case layers.LayerTypeUDP:
			rec.Flow = saveFlowPorts(rec.Flow, dir, uint8(layers.IPProtocolUDP), r.udp.SrcPort, r.udp.DstPort)
		case ndnlayer.LayerTypeTLV:
			rec.Size2 = len(r.tlv.LayerContents())
		case ndnlayer.LayerTypeNDN:
			pkt = r.ndn.Packet
		}
	}

	var pktType PktType
	switch {
	case pkt == nil:
		goto RETRY
	case pkt.Fragment != nil:
		pktType = PktTypeFragment
	case pkt.Interest != nil:
		pktType = PktTypeInterest
		rec.SaveInterest(*pkt.Interest, an.NackNone)
		zeroizeInterestPayload(pkt.Interest)
	case pkt.Data != nil:
		pktType = PktTypeData
		rec.SaveData(*pkt.Data)
		zeroizeDataPayload(pkt.Data)
	case pkt.Nack != nil:
		pktType = PktTypeNack
		rec.SaveInterest(pkt.Nack.Interest, pkt.Nack.Reason)
		zeroizeInterestPayload(&pkt.Nack.Interest)
	default:
		goto RETRY
	}

	rec.DirType = string(dir) + string(pktType)
	rec.Timestamp = rec.CaptureInfo.Timestamp.UnixNano()
	if ethOnly {
		rec.Flow = saveFlowAddrs(rec.Flow, dir, r.eth.SrcMAC, r.eth.DstMAC)
	}

	if frag := pkt.Fragment; frag != nil {
		if frag.FragIndex == 0 {
			r.readFragment(pkt.Lp, *frag, &rec)
		}
	} else {
		switch r.tlv.Element.Type {
		case an.TtInterest, an.TtData:
			rec.Size3 = r.tlv.Element.Size()
		case an.TtLpPacket:
			d := tlv.DecodingBuffer(r.tlv.Element.Value)
			for _, child := range d.Elements() {
				if child.Type == an.TtLpPayload {
					rec.Size3 = child.Length()
				}
			}
		}
	}

	rec.CaptureInfo.InterfaceIndex = 0
	rec.CaptureInfo.AncillaryData = nil
	return
}

func (Reader) readFragment(lpl3 ndn.LpL3, frag ndn.LpFragment, rec *Record) {
	var payload incompleteTLV
	if _, e := payload.Decode(frag.Payload); e != nil {
		return
	}

	switch payload.Type {
	case an.TtInterest:
		var interest ndn.Interest
		interest.UnmarshalBinary(payload.Value) // ignore error
		if lpl3.NackReason == an.NackNone {
			rec.DirType += string(PktTypeInterest)
		} else {
			rec.DirType += string(PktTypeNack)
		}
		rec.SaveInterest(interest, lpl3.NackReason)
	case an.TtData:
		var data ndn.Data
		data.UnmarshalBinary(payload.Value) // ignore error
		rec.DirType += string(PktTypeData)
		rec.SaveData(data)
	}
	rec.Size3 = payload.Size
}

// NewReader creates Reader.
func NewReader(src gopacket.ZeroCopyPacketDataSource, local net.HardwareAddr, ipa *IPAnonymizer) (r *Reader) {
	r = &Reader{
		src:   src,
		local: local,
		ipa:   ipa,
	}

	r.dlp = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &r.eth, &r.ip4, &r.ip6, &r.udp, &r.tlv, &r.ndn)
	r.dlp.IgnoreUnsupported = true
	return r
}

type incompleteTLV struct {
	Size   int
	Type   uint32
	Length int
	Value  []byte
}

func (ele *incompleteTLV) Decode(wire []byte) (rest []byte, e error) {
	var typ, length tlv.VarNum
	rest, e = typ.Decode(wire)
	if e != nil {
		return nil, e
	}
	rest, e = length.Decode(rest)
	if e != nil {
		return nil, e
	}
	ele.Type, ele.Length = uint32(typ), int(length)
	ele.Size = len(wire) - len(rest) + ele.Length

	if len(rest) >= ele.Length {
		ele.Value, rest = rest[:ele.Length], rest[ele.Length:]
	} else {
		ele.Value, rest = rest, nil
	}
	return rest, nil
}
