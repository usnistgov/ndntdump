package pcapinput

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/usnistgov/ndn-dpdk/core/macaddr"
	"github.com/zyedidia/generic/mapset"
)

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
