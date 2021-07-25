package main

import (
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type packetData struct {
	data []byte
	ipv6 bool
	pkt  gopacket.Packet
}

func newPacket(buf []byte) packetData {
	data := make([]byte, len(buf))
	copy(data, buf)

	ret := packetData{
		data: data,
	}
	ret.Parse()
	return ret
}

func (p *packetData) Parse() {
	version := p.data[0] & 0x0f
	is_ipv6 := version == 6

	p.ipv6 = is_ipv6
	if p.ipv6 {
		p.pkt = gopacket.NewPacket(p.data, layers.LayerTypeIPv6, gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})
	} else {
		p.pkt = gopacket.NewPacket(p.data, layers.LayerTypeIPv4, gopacket.DecodeOptions{
			Lazy:   true,
			NoCopy: true,
		})
	}
}

func (p *packetData) IPv6() bool {
	return p.ipv6
}

func (p *packetData) Protocol() (proto uint8) {
	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			proto = syscall.IPPROTO_TCP
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			proto = syscall.IPPROTO_UDP
		}
	}

	return
}

func (p *packetData) SrcIP() (srcip net.IP) {
	if p.ipv6 {
		ipv6 := p.pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		srcip = ipv6.SrcIP
	} else {
		ipv4 := p.pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		srcip = ipv4.SrcIP
	}

	return
}

func (p *packetData) SetSrcIP(srcip net.IP) {
	if p.ipv6 {
		ipv6 := p.pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ipv6.SrcIP = srcip
	} else {
		ipv4 := p.pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipv4.SrcIP = srcip
	}
}

func (p *packetData) DstIP() (dstip net.IP) {
	if p.ipv6 {
		ipv6 := p.pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		dstip = ipv6.DstIP
	} else {
		ipv4 := p.pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		dstip = ipv4.DstIP
	}

	return
}

func (p *packetData) SetDstIP(dstip net.IP) {
	if p.ipv6 {
		ipv6 := p.pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		ipv6.DstIP = dstip
	} else {
		ipv4 := p.pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipv4.DstIP = dstip
	}
}

func (p *packetData) SrcPort() (port uint16) {
	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			tcp := p.pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			port = uint16(tcp.SrcPort)
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			udp := p.pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			port = uint16(udp.SrcPort)
		}
	}

	return
}

func (p *packetData) SetSrcPort(port uint16) {
	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			tcp := p.pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			tcp.SrcPort = layers.TCPPort(port)
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			udp := p.pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			udp.SrcPort = layers.UDPPort(port)
		}
	}
}

func (p *packetData) DstPort() (port uint16) {
	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			tcp := p.pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			port = uint16(tcp.DstPort)
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			udp := p.pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			port = uint16(udp.DstPort)
		}
	}

	return
}

func (p *packetData) SetDstPort(port uint16) {
	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			tcp := p.pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			tcp.DstPort = layers.TCPPort(port)
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			udp := p.pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			udp.DstPort = layers.UDPPort(port)
		}
	}
}

func (p *packetData) Serialize() (data []byte, err error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	translayer := p.pkt.TransportLayer()
	if translayer != nil {
		if translayer.LayerType() == layers.LayerTypeTCP {
			tcp := p.pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			tcp.SetNetworkLayerForChecksum(p.pkt.NetworkLayer())
		} else if translayer.LayerType() == layers.LayerTypeUDP {
			udp := p.pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			udp.SetNetworkLayerForChecksum(p.pkt.NetworkLayer())
		}
	}

	err = gopacket.SerializePacket(buf, opts, p.pkt)
	if err != nil {
		return
	}

	p.data = buf.Bytes()
	data = p.data
	return
}
