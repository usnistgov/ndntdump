// Package pcapinput opens GoPacket input handle.
package pcapinput

import (
	"compress/gzip"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/klauspost/compress/zstd"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
	"github.com/zyedidia/generic/mapset"
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

type netifHandle struct {
	ifname  string
	locals  mapset.Set[[6]byte]
	tp      *afpacket.TPacket
	mu      sync.RWMutex
	closing atomic.Bool
}

func (hdl *netifHandle) open() (e error) {
	hdl.locals = mapset.New[[6]byte]()

	opts := []any{afpacket.OptPollTimeout(time.Second)}
	if hdl.ifname == "*" {
		netifs, e := net.Interfaces()
		if e != nil {
			return e
		}
		for _, netif := range netifs {
			if macaddr.IsUnicast(netif.HardwareAddr) {
				hdl.locals.Put([6]byte(netif.HardwareAddr))
			}
		}
	} else {
		netif, e := net.InterfaceByName(hdl.ifname)
		if e != nil {
			return e
		}
		hdl.locals.Put([6]byte(netif.HardwareAddr))
		opts = append(opts, afpacket.OptInterface(netif.Name))
	}

	hdl.tp, e = afpacket.NewTPacket(opts...)
	return e
}

func (hdl *netifHandle) Name() string {
	return hdl.ifname
}

func (hdl *netifHandle) IsLocal(mac net.HardwareAddr) bool {
	return hdl.locals.Has([6]byte(mac))
}

func (hdl *netifHandle) ZeroCopyReadPacketData() (wire []byte, ci gopacket.CaptureInfo, e error) {
	hdl.mu.RLock()
	defer hdl.mu.RUnlock()

	if hdl.closing.Load() {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}

RETRY:
	wire, ci, e = hdl.tp.ZeroCopyReadPacketData()
	if e != nil && errors.Is(e, afpacket.ErrTimeout) {
		if hdl.closing.Load() {
			e = io.EOF
		} else {
			goto RETRY
		}
	}

	return
}

func (hdl *netifHandle) Close() error {
	if wasClosed := hdl.closing.Swap(true); wasClosed {
		return nil
	}
	hdl.mu.Lock()
	defer hdl.mu.Unlock()
	hdl.tp.Close()
	return nil
}

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
