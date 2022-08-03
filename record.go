package ndn6dump

import (
	"github.com/google/gopacket"
	"github.com/usnistgov/ndn-dpdk/ndn"
)

// Direction indicates traffic direction.
type Direction string

// Direction values.
const (
	DirectionRX Direction = ">"
	DirectionTX Direction = "<"
)

// PktType indicates NDN packet type.
type PktType string

// PktType values.
const (
	PktTypeFragment PktType = "F"
	PktTypeInterest PktType = "I"
	PktTypeData     PktType = "D"
	PktTypeNack     PktType = "N"
	PktTypeIdle     PktType = "E"
)

// Record describes a parsed NDN packet.
type Record struct {
	Wire        []byte               `json:"-"`
	CaptureInfo gopacket.CaptureInfo `json:"-"`

	DirType   string `json:"t"`    // packet direction and type
	Timestamp int64  `json:"ts"`   // Unix epoch nanoseconds
	Flow      []byte `json:"flow"` // flow key
	Size      int    `json:"size"` // packet size at NDNLPv2 layer

	Name        ndn.Name `json:"name,omitempty"`       // packet name
	CanBePrefix bool     `json:"cbp,omitempty"`        // Interest CanBePrefix
	MustBeFresh bool     `json:"mbf,omitempty"`        // Interest MustBeFresh
	DataDigest  []byte   `json:"dataDigest,omitempty"` // Data implicit digest
	FinalBlock  bool     `json:"finalBlock,omitempty"` // Data is final block
}
