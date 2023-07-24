package main

import (
	"net"
	"path"
	"strings"
)

// // Get preferred outbound ip of this machine
func getOutboundIP(targetaddr string) (net.IP, error) {
	conn, err := net.Dial("udp", targetaddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

func getOutboundIface(targetaddr string) (*net.Interface, net.IP, error) {
	outboundIP, err := getOutboundIP(targetaddr)
	if err != nil {
		return nil, nil, err
	}

	ifces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, ifce := range ifces {
		addrs, err := ifce.Addrs()
		if err != nil {
			continue
		}

		matched := false
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip.Equal(outboundIP) {
				matched = true
				break
			}
		}

		if matched {
			return &ifce, outboundIP, nil
		}
	}

	return nil, nil, err
}

func compareProcessNames(target, compares string) bool {
	target = strings.ToLower(target)

	comparesArr := strings.Split(compares, "|")
	for _, compare := range comparesArr {
		compare = strings.ReplaceAll(compare, "\\", "/")
		compare = strings.ToLower(compare)
		if target == compare || path.Base(target) == compare {
			return true
		}
	}
	return false
}

/*
func hasOutboundFlag(flags uint8) bool {
	return flags&(1<<1) != 0
}
*/

// func hasLoopbackFlag(flags uint8) bool {
// 	return flags&(1<<2) != 0
// }

func hasIPv6Flag(flags uint8) bool {
	return flags&(1<<4) != 0
}

func setIPv6Flag(flags *uint8, on bool) {
	if on {
		*flags |= (1 << 4)
	} else {
		*flags &= 0xff ^ (1 << 4)
	}
}

func convertDivertAddressToNetIP(ipv6 bool, addr [16]byte) net.IP {
	ip := [16]byte{}
	if ipv6 {
		for i := 0; i < 16; i++ {
			ip[i] = addr[15-i]
		}
		return net.IP(ip[:])
	} else {
		for i := 0; i < 4; i++ {
			ip[i] = addr[3-i]
		}
		return net.IP(ip[:4])
	}
}
