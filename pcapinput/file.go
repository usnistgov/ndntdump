package pcapinput

import (
	"compress/gzip"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/klauspost/compress/zstd"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
)

type fileHandle struct {
	local      net.HardwareAddr
	file       *os.File
	decompress io.ReadCloser
	reader     *pcapgo.Reader
	ngr        *pcapgo.NgReader
}

func (hdl *fileHandle) open(filename string) (e error) {
	if hdl.file, e = os.Open(filename); e != nil {
		return e
	}
	pcapStream := io.Reader(hdl.file)

	ext := filepath.Ext(filename)
	switch ext {
	case ".gz":
		if hdl.decompress, e = gzip.NewReader(hdl.file); e != nil {
			return e
		}
		pcapStream = hdl.decompress
	case ".zst":
		if pcapStream, e = zstd.NewReader(hdl.file); e != nil {
			return e
		}
		hdl.decompress = io.NopCloser(pcapStream)
	}

	if hdl.decompress != nil {
		filename = filename[:len(filename)-len(ext)]
		ext = filepath.Ext(filename)
	}

	switch ext {
	case ".pcap":
		hdl.reader, e = pcapgo.NewReader(pcapStream)
	case ".pcapng":
		hdl.ngr, e = pcapgo.NewNgReader(pcapStream, pcapgo.NgReaderOptions{SkipUnknownVersion: true})
	default:
		return errors.New("unknown file extension")
	}
	return e
}

func (hdl *fileHandle) Name() string {
	if hdl.ngr != nil {
		if intf, e := hdl.ngr.Interface(0); e == nil {
			return intf.Name
		}
	}
	return hdl.file.Name()
}

func (hdl *fileHandle) IsLocal(mac net.HardwareAddr) bool {
	return macaddr.Equal(hdl.local, mac)
}

func (hdl *fileHandle) ZeroCopyReadPacketData() (wire []byte, ci gopacket.CaptureInfo, e error) {
	if hdl.reader != nil {
		return hdl.reader.ZeroCopyReadPacketData()
	}
	return hdl.ngr.ZeroCopyReadPacketData()
}

func (hdl *fileHandle) Close() error {
	errs := []error{}
	if hdl.decompress != nil {
		errs = append(errs, hdl.decompress.Close())
	}
	if hdl.file != nil {
		errs = append(errs, hdl.file.Close())
	}
	return errors.Join(errs...)
}
