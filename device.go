package main

import (
	"net"
	"os"

	"github.com/imgk/divert-go"
	"golang.zx2c4.com/wireguard/tun"
)

type netTun struct {
	events         chan tun.Event
	incomingPacket chan []byte
	mtu            int
	handle         *divert.Handle
	ifceIdx        int
	outboundIP     net.IP
	outboundIPv6   net.IP
}

func newTun(mtu int, handle *divert.Handle, incomingPacket chan []byte, ifceIdx int, outboundIP, outboundIPv6 net.IP) *netTun {
	t := &netTun{
		events:         make(chan tun.Event, 10),
		incomingPacket: incomingPacket,
		mtu:            mtu,
		handle:         handle,
		ifceIdx:        ifceIdx,
		outboundIP:     outboundIP,
		outboundIPv6:   outboundIPv6,
	}
	t.events <- tun.EventUp
	return t
}

func (tun *netTun) Name() (string, error) {
	return "divert", nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for i, buf := range bufs {
		data, ok := <-tun.incomingPacket
		if !ok {
			return i, os.ErrClosed
		}
		copy(buf[offset:], data)
		sizes[i] = len(data)
	}

	return len(bufs), nil
}

func (tun *netTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkt := newPacket(packet)
		is_ipv6 := pkt.IPv6()

		var dstip net.IP
		if is_ipv6 {
			dstip = tun.outboundIPv6
		} else {
			dstip = tun.outboundIP
		}

		addr := divert.Address{}
		addr.SetLayer(divert.LayerNetwork)
		addr.SetEvent(divert.EventNetworkPacket)
		addr.Network().InterfaceIndex = uint32(tun.ifceIdx)
		addr.Network().SubInterfaceIndex = 0
		setIPv6Flag(&addr.Flags, is_ipv6)
		pkt.SetDstIP(dstip)

		data, err := pkt.Serialize()
		if err != nil {
			return i, err
		}

		_, err = tun.handle.Send(data, &addr)
		if err != nil {
			return i, err
		}
		continue
	}

	return len(bufs), nil
}

func (tun *netTun) Flush() error {
	return nil
}

func (tun *netTun) Close() error {
	if tun.events != nil {
		close(tun.events)
	}
	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}
	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *netTun) BatchSize() int {
	return 1
}
