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
)

// Record describes a parsed NDN packet.
type Record struct {
	Wire        []byte               `json:"-"`
	CaptureInfo gopacket.CaptureInfo `json:"-"`

	DirType   string `json:"t"`     // packet direction and type
	Timestamp int64  `json:"ts"`    // Unix epoch nanoseconds
	Flow      []byte `json:"flow"`  // flow key
	Size2     int    `json:"size2"` // packet size at NDNLPv2 layer

	Size3       int      `json:"size3,omitempty"`      // packet size at L3
	NackReason  uint8    `json:"nackReason,omitempty"` // Nack reason
	Name        ndn.Name `json:"name,omitempty"`       // packet name
	CanBePrefix bool     `json:"cbp,omitempty"`        // Interest CanBePrefix
	MustBeFresh bool     `json:"mbf,omitempty"`        // Interest MustBeFresh
	FinalBlock  bool     `json:"finalBlock,omitempty"` // Data is final block
}

func (rec *Record) SaveInterest(interest ndn.Interest, nackReason uint8) {
	rec.Name = interest.Name
	rec.CanBePrefix = interest.CanBePrefix
	rec.MustBeFresh = interest.MustBeFresh
	rec.NackReason = nackReason
}

func (rec *Record) SaveData(data ndn.Data) {
	rec.Name = data.Name
	rec.FinalBlock = data.IsFinalBlock()
}
