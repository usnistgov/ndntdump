package fileoutput

import (
	"errors"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/usnistgov/ndntdump"
)

// PcapngOutput saves packet bytes in pcapng file.
type PcapngOutput struct {
	cf  *compressedFile
	ngw *pcapgo.NgWriter
}

func (o *PcapngOutput) Close() error {
	return errors.Join(
		o.ngw.Flush(),
		o.cf.Close(),
	)
}

func (o *PcapngOutput) Write(rec ndntdump.Record) error {
	if len(rec.Wire) == 0 {
		return nil
	}
	rec.CaptureInfo.InterfaceIndex = 0
	rec.CaptureInfo.AncillaryData = nil
	return o.ngw.WritePacket(rec.CaptureInfo, rec.Wire)
}

// NewPcapngOutput creates PcapngOutput.
func NewPcapngOutput(filename string) (o *PcapngOutput, e error) {
	o = &PcapngOutput{}
	if o.cf, e = newCompressedFile(filename); e != nil {
		return nil, e
	}
	if o.ngw, e = pcapgo.NewNgWriter(o.cf, layers.LinkTypeEthernet); e != nil {
		o.cf.Close()
		return nil, e
	}
	return o, nil
}
