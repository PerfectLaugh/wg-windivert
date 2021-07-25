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
	outboundIPv4   net.IP
	outboundIPv6   net.IP
	ifceIdx        int
}

func newTun(mtu int, handle *divert.Handle, incomingPacket chan []byte, outboundIPv4, outboundIPv6 net.IP, ifceIdx int) *netTun {
	t := &netTun{
		events:         make(chan tun.Event, 10),
		incomingPacket: incomingPacket,
		mtu:            mtu,
		handle:         handle,
		outboundIPv4:   outboundIPv4,
		outboundIPv6:   outboundIPv6,
		ifceIdx:        ifceIdx,
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

func (tun *netTun) Events() chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(buf []byte, offset int) (int, error) {
	data, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	return copy(buf[offset:], data), nil
}

func (tun *netTun) Write(buf []byte, offset int) (int, error) {
	packet := buf[offset:]
	if len(packet) == 0 {
		return 0, nil
	}

	version := packet[0] & 0x0f
	ipv6 := version == 6

	addr := divert.Address{}
	addr.SetLayer(divert.LayerNetwork)
	addr.SetEvent(divert.EventNetworkPacket)
	addr.Network().InterfaceIndex = uint32(tun.ifceIdx)
	addr.Network().SubInterfaceIndex = 0
	setIPv6Flag(&addr.Flags, ipv6)

	pkt := newPacket(packet)

	if ipv6 {
		pkt.SetDstIP(tun.outboundIPv6)
	} else {
		pkt.SetDstIP(tun.outboundIPv4)
	}

	data, err := pkt.Serialize()
	if err != nil {
		return 0, err
	}

	n, err := tun.handle.Send(data, &addr)
	return int(n), err
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
