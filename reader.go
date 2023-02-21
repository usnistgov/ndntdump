package ndntdump

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
	"github.com/usnistgov/ndn-dpdk/ndn"
	"github.com/usnistgov/ndn-dpdk/ndn/an"
	"github.com/usnistgov/ndn-dpdk/ndn/ndnlayer"
	"github.com/usnistgov/ndn-dpdk/ndn/tlv"
	"github.com/usnistgov/ndntdump/websocket"
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

func saveFlowPorts[P ~uint8, N ~uint16](flow []byte, dir Direction, proto P, src, dst N) []byte {
	if dir == DirectionRX {
		src, dst = dst, src
	}
	return append(flow, uint8(proto), uint8(src>>8), uint8(src), uint8(dst>>8), uint8(dst))
}

// Reader reads NDN packets from ZeroCopyPacketDataSource.
type Reader struct {
	src     gopacket.ZeroCopyPacketDataSource
	local   net.HardwareAddr
	wssPort layers.TCPPort
	anon    *Anonymizer

	dlp     *gopacket.DecodingLayerParser
	dlpTLV  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	udp     layers.UDP
	tcp     layers.TCP
	tlv     ndnlayer.TLV
	ndn     ndnlayer.NDN

	dir    Direction
	unread []Record
}

// Read reads an NDN packet.
//
// []byte fields within returned structure are valid until next call to this function.
func (r *Reader) Read() (rec Record, e error) {
	if len(r.unread) > 0 {
		rec = r.unread[0]
		r.unread = r.unread[1:]
		return
	}

RETRY:
	rec = Record{}
	if rec.Wire, rec.CaptureInfo, e = r.src.ZeroCopyReadPacketData(); e != nil {
		return
	}

	if e = r.dlp.DecodeLayers(rec.Wire, &r.decoded); e != nil {
		goto RETRY
	}

	for _, layerType := range r.decoded {
		switch layerType {
		case layers.LayerTypeEthernet:
			switch {
			case macaddr.Equal(r.eth.SrcMAC, r.eth.DstMAC):
				if len(r.decoded) >= 3 && r.decoded[2] == layers.LayerTypeTCP {
					switch r.wssPort {
					case r.tcp.SrcPort:
						r.dir = DirectionTX
					case r.tcp.DstPort:
						r.dir = DirectionRX
					default:
						goto RETRY
					}
				}
			case macaddr.Equal(r.local, r.eth.SrcMAC):
				r.dir = DirectionTX
			case macaddr.Equal(r.local, r.eth.DstMAC):
				r.dir = DirectionRX
			default:
				goto RETRY
			}
			r.anon.AnonymizeMAC(r.eth.SrcMAC)
			r.anon.AnonymizeMAC(r.eth.DstMAC)
			rec.Flow = saveFlowAddrs(nil, r.dir, r.eth.SrcMAC, r.eth.DstMAC)
		case layers.LayerTypeIPv4:
			r.anon.AnonymizeIP(r.ip4.SrcIP)
			r.anon.AnonymizeIP(r.ip4.DstIP)
			rec.Flow = saveFlowAddrs(nil, r.dir, r.ip4.SrcIP, r.ip4.DstIP)
		case layers.LayerTypeIPv6:
			r.anon.AnonymizeIP(r.ip6.SrcIP)
			r.anon.AnonymizeIP(r.ip6.DstIP)
			rec.Flow = saveFlowAddrs(nil, r.dir, r.ip6.SrcIP, r.ip6.DstIP)
		case layers.LayerTypeUDP:
			rec.Flow = saveFlowPorts(rec.Flow, r.dir, layers.IPProtocolUDP, r.udp.SrcPort, r.udp.DstPort)
		case layers.LayerTypeTCP:
			rec.Flow = saveFlowPorts(rec.Flow, r.dir, layers.IPProtocolTCP, r.tcp.SrcPort, r.tcp.DstPort)
			r.readWebSocket(rec.CaptureInfo, rec.Flow)
			return rec, nil
		case ndnlayer.LayerTypeTLV:
			rec.Size2 = len(r.tlv.LayerContents())
		case ndnlayer.LayerTypeNDN:
			if r.readPacket(&rec) {
				return rec, nil
			}
		}
	}

	goto RETRY
}

func (r *Reader) readWebSocket(ci gopacket.CaptureInfo, flow []byte) {
	if len(r.tcp.Payload) == 0 {
		return
	}

	frames, _ := websocket.ExtractBinaryFrames(r.tcp.Payload)
	if len(frames) == 0 {
		websocket.AnonymizeXForwardedFor(r.tcp.Payload)
		return
	}

	r.unread = make([]Record, 0, len(frames))
	for _, f := range frames {
		if e := r.dlpTLV.DecodeLayers(f.Payload, &r.decoded); e != nil {
			continue
		}

		rec := Record{CaptureInfo: ci, Flow: flow}
		for _, layerType := range r.decoded {
			switch layerType {
			case ndnlayer.LayerTypeTLV:
				rec.Size2 = len(r.tlv.LayerContents())
			case ndnlayer.LayerTypeNDN:
				if r.readPacket(&rec) {
					r.unread = append(r.unread, rec)
				}
			}
		}
	}
}

func (r *Reader) readPacket(rec *Record) bool {
	pkt := r.ndn.Packet
	var pktType PktType
	switch {
	case pkt == nil:
		return false
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
		return false
	}

	rec.DirType = string(r.dir) + string(pktType)
	rec.Timestamp = rec.CaptureInfo.Timestamp.UnixNano()

	if frag := pkt.Fragment; frag != nil {
		if frag.FragIndex == 0 {
			r.readFragment(pkt.Lp, *frag, rec)
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
	return true
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
func NewReader(src gopacket.ZeroCopyPacketDataSource, opts ReaderOptions) (r *Reader) {
	r = &Reader{
		src:     src,
		local:   opts.Local,
		wssPort: layers.TCPPort(opts.WebSocketPort),
		anon:    opts.Anonymizer,
	}
	if r.wssPort == 0 {
		r.wssPort = 9696
	}

	r.dlp = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &r.eth, &r.ip4, &r.ip6, &r.udp, &r.tcp, &r.tlv, &r.ndn)
	r.dlp.IgnoreUnsupported = true
	r.dlpTLV = gopacket.NewDecodingLayerParser(ndnlayer.LayerTypeTLV, &r.tlv, &r.ndn)
	r.dlpTLV.IgnoreUnsupported = true
	return r
}

// ReaderOptions passes options to NewReader.
type ReaderOptions struct {
	Local         net.HardwareAddr
	WebSocketPort int
	Anonymizer    *Anonymizer
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
