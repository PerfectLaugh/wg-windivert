package main

import (
	"container/list"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/imgk/divert-go"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

var PRIORITY = 100

type sendElement struct {
	pkt  packetData
	addr divert.Address
}

type sendQueue struct {
	mu             sync.Mutex
	portMapping    map[uint16]*list.List
	timer          *time.Timer
	handle         *divert.Handle
	incomingPacket chan []byte
}

func newSendQueue(handle *divert.Handle, incomingPacket chan []byte) *sendQueue {
	q := &sendQueue{
		portMapping:    make(map[uint16]*list.List),
		timer:          time.NewTimer(0),
		handle:         handle,
		incomingPacket: incomingPacket,
	}
	<-q.timer.C
	return q
}

func (q *sendQueue) Run() {
	for {
		var pkts []sendElement

		q.timer.Reset(10 * time.Millisecond)
		<-q.timer.C

		pkts = q.PopAll()

		for _, pkt := range pkts {
			q.CheckAndSendPacket(&pkt.pkt, &pkt.addr)
		}
	}
}

func (q *sendQueue) Bind(port uint16) {
	q.mu.Lock()
	defer q.mu.Unlock()

	l, ok := q.portMapping[port]
	if ok && l != nil {
		for l.Front() != nil {
			pkt := l.Remove(l.Front()).(sendElement)
			q.CheckAndSendPacket(&pkt.pkt, &pkt.addr)
		}
	}
	q.portMapping[port] = nil
}

func (q *sendQueue) Close(port uint16) {
	q.mu.Lock()
	defer q.mu.Unlock()

	delete(q.portMapping, port)
}

func (q *sendQueue) HasSeenPort(port uint16) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	l, ok := q.portMapping[port]
	return ok && l == nil
}

func (q *sendQueue) Push(port uint16, pkt sendElement) {
	q.mu.Lock()
	defer q.mu.Unlock()

	l, ok := q.portMapping[port]
	if !ok {
		q.portMapping[port] = list.New()
		l = q.portMapping[port]
	}

	l.PushBack(pkt)
}

func (q *sendQueue) PopAll() []sendElement {
	q.mu.Lock()
	defer q.mu.Unlock()

	pkts := make([]sendElement, 0)
	for _, l := range q.portMapping {
		if l == nil {
			continue
		}
		for l.Front() != nil {
			pkt := l.Remove(l.Front()).(sendElement)
			pkts = append(pkts, pkt)
		}
	}
	return pkts
}

func (q *sendQueue) CheckAndSendPacket(pkt *packetData, address *divert.Address) {
	proto := pkt.Protocol()
	srcip := pkt.SrcIP()
	srcport := pkt.SrcPort()

	if !hasLoopbackFlag(address.Flags) && proto != 0 {
		if mapper.ShouldBeIntercepted(proto, srcip, srcport) {
			if hasIPv6Flag(address.Flags) {
				pkt.SetSrcIP(net.ParseIP(*internalIPv6))
			} else {
				pkt.SetSrcIP(net.ParseIP(*internalIPv4))
			}
			data, err := pkt.Serialize()
			if err != nil {
				log.Println("could not serialize packet:", err)
			}
			q.incomingPacket <- data

			return
		}
	}

	if _, err := q.handle.Send(pkt.data, address); err != nil {
		panic(err)
	}
}

type endpointKey struct {
	proto     uint8
	localip   string
	localport uint16
	//remoteaddr [16]uint8
	//remoteport uint16
}

type endpointValue struct {
}

type endpointMapper struct {
	mu       sync.Mutex
	localmap map[endpointKey]endpointValue
}

func newMapper() endpointMapper {
	return endpointMapper{
		localmap: make(map[endpointKey]endpointValue),
	}
}

func (m *endpointMapper) GetLocalAddrMapping(proto uint8, localport uint16) (localip net.IP) {
	for k := range m.localmap {
		if k.localport == localport {
			localip = net.IP(k.localip)
			break
		}
	}

	return
}

func (m *endpointMapper) ShouldBeIntercepted(proto uint8, localip net.IP, localport uint16) bool {
	mapper.mu.Lock()
	defer mapper.mu.Unlock()

	for k := range m.localmap {
		if k.proto != proto || k.localport != localport {
			continue
		}

		ip := net.IP(k.localip)
		if ip.IsUnspecified() {
			return true
		}
		if ip.Equal(localip) {
			return true
		}
	}

	return false
}

func (m *endpointMapper) AddEndpoint(proto uint8, localip net.IP, localport uint16) {
	mapper.mu.Lock()
	defer mapper.mu.Unlock()

	key := endpointKey{
		proto:     proto,
		localip:   string(localip.To16()),
		localport: localport,
	}
	m.localmap[key] = endpointValue{}
}

func (m *endpointMapper) RemoveEndpoint(proto uint8, localip net.IP, localport uint16) {
	mapper.mu.Lock()
	defer mapper.mu.Unlock()

	key := endpointKey{
		proto:     proto,
		localip:   string(localip.To16()),
		localport: localport,
	}
	delete(m.localmap, key)
}

var mapper = newMapper()
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

		port := packet.SrcPort()
		if !sender.HasSeenPort(port) {
			sender.Push(port, sendElement{
				pkt:  packet,
				addr: address,
			})
			continue
		}

		sender.CheckAndSendPacket(&packet, &address)
	}
}

func runSocketFilter() {
	handle, err := divert.Open("true", divert.LayerSocket, int16(PRIORITY+100), divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Fatal("runSocketFilter error:", err)
	}

	buf := make([]byte, 65535)
	for {
		address := divert.Address{}
		_, err := handle.Recv(buf, &address)
		if err != nil {
			log.Fatal(err)
		}

		socket := address.Socket()
		evt := address.Event()

		ipv6 := hasIPv6Flag(address.Flags)
		srcip := convertDivertAddressToNetIP(ipv6, socket.LocalAddress)

		protocolStr := "unknown"
		switch socket.Protocol {
		case syscall.IPPROTO_TCP:
			protocolStr = "tcp"
		case syscall.IPPROTO_UDP:
			protocolStr = "udp"
		}

		procPath, err := processPidToName(socket.ProcessID)
		procPath = strings.ReplaceAll(procPath, "\\", "/")

		if evt == divert.EventSocketBind {
			if err == nil && compareProcessNames(path.Base(procPath), *targetProcessName) {
				log.Println("bind:", socket.ProcessID, procPath, protocolStr, srcip, socket.LocalPort)
				mapper.AddEndpoint(socket.Protocol, srcip, socket.LocalPort)
			}
			sender.Bind(socket.LocalPort)
		} else if evt == divert.EventSocketClose {
			if err == nil && compareProcessNames(path.Base(procPath), *targetProcessName) {
				log.Println("close:", socket.ProcessID, procPath, protocolStr, srcip, socket.LocalPort)
				mapper.RemoveEndpoint(socket.Protocol, srcip, socket.LocalPort)
			}
			sender.Close(socket.LocalPort)
		}
	}
}

var targetProcessName = flag.String("name", "", "Target Process Name(s)")
var privKey = flag.String("privkey", "", "Client Private Key")
var publicKey = flag.String("pubkey", "", "Server Public Key")
var endpoint = flag.String("endpoint", "", "Server Endpoint")
var internalIPv4 = flag.String("ipv4", "0.0.0.0", "Internal IPv4 in WireGuard")
var internalIPv6 = flag.String("ipv6", "::", "Internal IPv6 in WireGuard")

func main() {
	flag.Parse()

	handle, err := divert.Open("outbound", divert.LayerNetwork, int16(PRIORITY), divert.FlagDefault)
	if err != nil {
		log.Fatal("open divert handle error:", err)
	}

	incomingPacket := make(chan []byte)

	sender = newSendQueue(handle, incomingPacket)

	iface, outip4, err := getOutboundIface("8.8.8.8:53")
	if err != nil {
		log.Fatal("could not get outbound iface:", err)
	}
	_, outip6, _ := getOutboundIface("[2001:4860:4860::8888]:53")

	t := newTun(1500, handle, incomingPacket, outip4, outip6, iface.Index)
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
`, pubKeyStr, *endpoint))
	dev.Up()

	go sender.Run()
	go runSocketFilter()
	runInjectFilter(handle)
}
