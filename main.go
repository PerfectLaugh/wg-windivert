package main

import (
	"container/list"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/imgk/divert-go"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var PRIORITY = 100

var outboundIP net.IP
var outboundIPv6 net.IP

type sendAddress struct {
	is_ipv6 bool
	proto   uint8
	port    uint16
}

type sendQueue struct {
	mu             sync.Mutex
	mapping        map[sendAddress]bool
	pending        map[sendAddress]*list.List
	pending_timer  map[sendAddress]*time.Timer
	handle         *divert.Handle
	incomingPacket chan []byte
}

func newSendQueue(handle *divert.Handle, incomingPacket chan []byte) *sendQueue {
	q := &sendQueue{
		mapping:        make(map[sendAddress]bool),
		pending:        make(map[sendAddress]*list.List),
		pending_timer:  make(map[sendAddress]*time.Timer),
		handle:         handle,
		incomingPacket: incomingPacket,
	}
	return q
}

func (q *sendQueue) Lock() {
	q.mu.Lock()
}

func (q *sendQueue) Unlock() {
	q.mu.Unlock()
}

func (q *sendQueue) Bind(is_ipv6 bool, proto uint8, port uint16) {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	_, ok := q.mapping[addr]
	if !ok {
		q.mapping[addr] = true
	}
	q.popQueue(is_ipv6, proto, port, true)
}

func (q *sendQueue) BindOther(is_ipv6 bool, proto uint8, port uint16) {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	_, ok := q.mapping[addr]
	if !ok {
		q.mapping[addr] = false
	}
	q.popQueue(is_ipv6, proto, port, false)
}

func (q *sendQueue) popQueue(is_ipv6 bool, proto uint8, port uint16, interceptee bool) {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	l, ok := q.pending[addr]
	if ok {
		for c := l.Front(); c != nil; c = c.Next() {
			pkt := c.Value.(sendElement)
			if interceptee {
				q.SendPacket(pkt.pkt, pkt.addr)
			} else {
				q.handle.Send(pkt.pkt.data, pkt.addr)
			}
		}
	}

	delete(q.pending, addr)
}

func (q *sendQueue) Close(is_ipv6 bool, proto uint8, port uint16) {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	delete(q.mapping, addr)
}

func (q *sendQueue) EntryExists(is_ipv6 bool, proto uint8, port uint16) bool {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	_, ok := q.mapping[addr]
	return ok
}

func (q *sendQueue) IsInterceptee(is_ipv6 bool, proto uint8, port uint16) bool {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	return q.mapping[addr]
}

func (q *sendQueue) QueuePacket(is_ipv6 bool, proto uint8, port uint16, pkt *packetData, address *divert.Address) {
	addr := sendAddress{
		is_ipv6: is_ipv6,
		proto:   proto,
		port:    port,
	}

	l, ok := q.pending[addr]
	if !ok {
		l = list.New()
		q.pending[addr] = l
	}

	l.PushBack(sendElement{pkt, address})

	if _, ok := q.pending_timer[addr]; !ok {
		timer := time.NewTimer(10 * time.Millisecond)
		q.pending_timer[addr] = timer
		go func() {
			defer timer.Stop()
			<-timer.C

			q.Lock()
			defer q.Unlock()

			if !q.EntryExists(is_ipv6, proto, port) {
				q.BindOther(is_ipv6, proto, port)
			}
			delete(q.pending_timer, addr)
		}()
	}
}

func (q *sendQueue) SendPacket(pkt *packetData, address *divert.Address) {
	if pkt.Protocol() != 0 {
		if pkt.IPv6() {
			pkt.SetSrcIP(net.ParseIP(*internalIPv6))
		} else {
			pkt.SetSrcIP(net.ParseIP(*internalIPv4))
		}

		data, err := pkt.Serialize()
		if err != nil {
			log.Fatal("could not serialize packet:", err)
		}
		q.incomingPacket <- data

		return
	}

	if _, err := q.handle.Send(pkt.data, address); err != nil {
		panic(err)
	}
}

type sendElement struct {
	pkt  *packetData
	addr *divert.Address
}

var sender *sendQueue

func runInjectFilter(handle *divert.Handle) {
	buf := make([]byte, 65535)
	for {
		address := divert.Address{}
		n, err := handle.Recv(buf, &address)
		if err != nil {
			log.Fatal("could not recv packet:", err)
		}

		packet := newPacket(buf[:n])
		if packet.Protocol() == 0 {
			_, err := handle.Send(packet.data, &address)
			if err != nil {
				panic(err)
			}
			continue
		}

		is_ipv6 := hasIPv6Flag(address.Flags)
		srcport := packet.SrcPort()
		protocol := packet.Protocol()

		sender.Lock()

		if !sender.EntryExists(is_ipv6, protocol, srcport) {
			sender.QueuePacket(is_ipv6, protocol, srcport, &packet, &address)
		} else if sender.IsInterceptee(is_ipv6, protocol, srcport) {
			sender.SendPacket(&packet, &address)
		} else {
			handle.Send(buf, &address)
		}

		sender.Unlock()
	}
}

func runSocketFilter() {
	handle, err := divert.Open("outbound and not loopback", divert.LayerSocket, int16(PRIORITY+100), divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Fatal("runSocketFilter error:", err)
	}

	buf := make([]byte, 65535)
	var address divert.Address
	for {
		_, err := handle.Recv(buf, &address)
		if err != nil {
			log.Fatal(err)
		}

		socket := address.Socket()
		evt := address.Event()

		if evt != divert.EventSocketConnect && evt != divert.EventSocketClose {
			continue
		}

		is_ipv6 := hasIPv6Flag(address.Flags)
		srcip := convertDivertAddressToNetIP(is_ipv6, socket.LocalAddress)
		if srcip.IsUnspecified() {
			continue
		}
		if is_ipv6 && !outboundIPv6.Equal(srcip) {
			continue
		} else if !is_ipv6 && !outboundIP.Equal(srcip) {
			continue
		}

		protocolStr := "unknown"
		switch socket.Protocol {
		case syscall.IPPROTO_TCP:
			protocolStr = "tcp"
		case syscall.IPPROTO_UDP:
			protocolStr = "udp"
		}

		procPath, err := processPidToName(socket.ProcessID)
		procPath = strings.ReplaceAll(procPath, "\\", "/")

		sender.Lock()
		if evt == divert.EventSocketConnect {
			if err == nil && compareProcessNames(procPath, *targetProcessName) {
				log.Println("bind:", is_ipv6, socket.ProcessID, procPath, protocolStr, srcip, socket.LocalPort)
				sender.Bind(is_ipv6, socket.Protocol, socket.LocalPort)
			} else {
				sender.BindOther(is_ipv6, socket.Protocol, socket.LocalPort)
			}
		} else if evt == divert.EventSocketClose {
			if err == nil && compareProcessNames(procPath, *targetProcessName) {
				log.Println("close:", is_ipv6, socket.ProcessID, procPath, protocolStr, srcip, socket.LocalPort)
			}
			sender.Close(is_ipv6, socket.Protocol, socket.LocalPort)
		}

		sender.Unlock()
	}
}

var targetProcessName = flag.String("name", "", "Target Process Name(s), use '|' as seperator")
var privKey = flag.String("privkey", "", "Client Private Key")
var publicKey = flag.String("pubkey", "", "Server Public Key")
var psk = flag.String("psk", "", "Preshared Key")
var endpoint = flag.String("endpoint", "", "Server Endpoint")
var internalIPv4 = flag.String("ipv4", "0.0.0.0", "Internal IPv4 in WireGuard")
var internalIPv6 = flag.String("ipv6", "::", "Internal IPv6 in WireGuard")

func main() {
	flag.Parse()

	handle, err := divert.Open("outbound and not loopback", divert.LayerNetwork, int16(PRIORITY), divert.FlagDefault)
	if err != nil {
		log.Fatal("open divert handle error:", err)
	}

	incomingPacket := make(chan []byte)

	var iface *net.Interface
	iface, outboundIP, err = getOutboundIface("8.8.8.8:53")
	if err != nil {
		log.Fatal("could not get outbound iface:", err)
	}
	_, outboundIPv6, _ = getOutboundIface("[2001:4860:4860::8888]:53")

	sender = newSendQueue(handle, incomingPacket)

	t := newTun(1500, handle, incomingPacket, iface.Index, outboundIP, outboundIPv6)
	dev := device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	privKeyBytes, err := base64.StdEncoding.DecodeString(*privKey)
	if err != nil {
		log.Fatal("could not parse private key:", err)
	}
	privKeyStr := hex.EncodeToString(privKeyBytes)

	pubKeyBytes, err := base64.StdEncoding.DecodeString(*publicKey)
	if err != nil {
		log.Fatal("could not parse public key:", err)
	}
	pubKeyStr := hex.EncodeToString(pubKeyBytes)

	dev.IpcSet(fmt.Sprintf("private_key=%s", privKeyStr))
	dev.IpcSet(fmt.Sprintf(`public_key=%s
endpoint=%s
allowed_ip=0.0.0.0/0
allowed_ip=::/0
`, pubKeyStr, *endpoint))
	if *psk != "" {
		pskBytes, err := base64.StdEncoding.DecodeString(*psk)
		if err != nil {
			log.Fatal("could not parse preshared key:", err)
		}
		pskStr := hex.EncodeToString(pskBytes)
		dev.IpcSet(fmt.Sprintf("preshared_key=%s", pskStr))
	}

	dev.Up()

	go runSocketFilter()
	runInjectFilter(handle)
}
