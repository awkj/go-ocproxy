package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/awkj/go-ocproxy/netstack"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestUDPDatagrams(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "vpn.example"} {
		packet := appendUDPHeader(nil, host, 53)
		packet = append(packet, []byte("hello")...)
		target, port, payload, err := parseUDPDatagram(packet)
		if err != nil || target != host || port != 53 || string(payload) != "hello" {
			t.Fatalf("%s: %s %d %q %v", host, target, port, payload, err)
		}
	}
	valid := appendUDPHeader(nil, "127.0.0.1", 53)
	for n := 0; n < len(valid); n++ {
		if _, _, _, err := parseUDPDatagram(valid[:n]); err == nil {
			t.Fatalf("accepted short packet %d", n)
		}
	}
	for _, packet := range [][]byte{{0, 0, 1, 1, 127, 0, 0, 1, 0, 53}, {1, 0, 0, 1, 127, 0, 0, 1, 0, 53}, {0, 0, 0, 3, 0, 0, 53}, {0, 0, 0, 1, 127, 0, 0, 1, 0, 0}} {
		if _, _, _, err := parseUDPDatagram(packet); err == nil {
			t.Fatalf("accepted malformed %x", packet)
		}
	}
}

// 无需 VPN：在 relay 边界注入真实 UDP echo，验证双向封装、源端口约束与清理。
func TestUDPAssociateRelay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	control, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := echo.ReadFromUDP(b)
			if e != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	source, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer control.Close()
		relayUDPWithLimits(context.Background(), control, uint16(source.LocalAddr().(*net.UDPAddr).Port), func(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
			c, e := net.DialUDP("udp4", nil, echo.LocalAddr().(*net.UDPAddr))
			return c, "127.0.0.1", e
		}, 1, 100*time.Millisecond)
	}()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("reply %x", reply)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(reply[8])<<8 | int(reply[9])}
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	packet := append(appendUDPHeader(nil, "127.0.0.1", 53), []byte("echo")...)
	attacker.WriteToUDP(packet, relay)
	attacker.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	b := make([]byte, 65535)
	if _, _, err := attacker.ReadFromUDP(b); err == nil {
		t.Fatal("wrong source port received response")
	}
	source.WriteToUDP(packet, relay)
	source.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := source.ReadFromUDP(b)
	if err != nil || !bytes.Equal(b[:n], packet) {
		t.Fatalf("echo %x %v", b[:n], err)
	}
	second := append(appendUDPHeader(nil, "127.0.0.1", 54), []byte("limit")...)
	source.WriteToUDP(second, relay)
	source.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := source.ReadFromUDP(b); err == nil {
		t.Fatal("target limit not enforced")
	}
	time.Sleep(150 * time.Millisecond)
	source.WriteToUDP(second, relay)
	source.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = source.ReadFromUDP(b)
	if err != nil || !bytes.Equal(b[:n], second) {
		t.Fatalf("idle target not reclaimed: %x %v", b[:n], err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay survived control close")
	}
}

// 真实 gVisor UDP endpoint：从完整 SOCKS5 握手到隧道栈回包，覆盖域名解析与首包来源固定。
func TestUDPAssociateNetstack(t *testing.T) {
	s, address := setupTestServer(t)
	peerStack, err := netstack.New("10.0.0.2", 1500, "")
	if err != nil {
		t.Fatal(err)
	}
	bridgeCtx, stopBridge := context.WithCancel(context.Background())
	var bridgeWG sync.WaitGroup
	for _, direction := range [][2]*netstack.NetStack{{s.ns, peerStack}, {peerStack, s.ns}} {
		from, to := direction[0], direction[1]
		bridgeWG.Go(func() {
			for {
				packet := from.Link.ReadContext(bridgeCtx)
				if packet == nil {
					return
				}
				data := packet.ToBuffer()
				inbound := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(bytes.Clone(data.Flatten()))})
				data.Release()
				packet.DecRef()
				to.Link.InjectInbound(ipv4.ProtocolNumber, inbound)
				inbound.DecRef()
			}
		})
	}
	t.Cleanup(func() { s.Close(time.Second); stopBridge(); bridgeWG.Wait(); peerStack.Close(); s.ns.Close() })
	endpoint, err := gonet.DialUDP(peerStack.Stack, &tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), Port: 5353}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, e := endpoint.ReadFrom(b)
			if e != nil {
				return
			}
			endpoint.WriteTo(b[:n], from)
		}
	}()
	s.cache.set("udp.vpn.example", net.IPv4(10, 0, 0, 2), time.Minute)
	client := dialTest(t, address)
	defer client.Close()
	client.Write([]byte{5, 1, 0})
	auth := make([]byte, 2)
	if _, err := io.ReadFull(client, auth); err != nil {
		t.Fatal(err)
	}
	client.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("UDP handshake %x", reply)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:10]))}
	source, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	attacker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	packet := append(appendUDPHeader(nil, "udp.vpn.example", 5353), []byte("netstack")...)
	malformed := bytes.Clone(packet)
	malformed[2] = 1
	attacker.WriteToUDP(malformed, relay)
	source.WriteToUDP(packet, relay)
	source.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 65535)
	n, _, err := source.ReadFromUDP(b)
	expected := append(appendUDPHeader(nil, "10.0.0.2", 5353), []byte("netstack")...)
	if err != nil || !bytes.Equal(b[:n], expected) {
		t.Fatalf("netstack echo %x %v", b[:n], err)
	}
	attacker.WriteToUDP(packet, relay)
	attacker.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	if _, _, err := attacker.ReadFromUDP(b); err == nil {
		t.Fatal("second source took over UDP association")
	}
	client.Close()
}

func TestUDPAssociateRejectsForeignSource(t *testing.T) {
	_, address := setupTestServer(t)
	control := dialTest(t, address)
	defer control.Close()
	control.Write([]byte{5, 1, 0})
	auth := make([]byte, 2)
	io.ReadFull(control, auth)
	control.Write([]byte{5, 3, 0, 1, 192, 0, 2, 1, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(control, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 2 {
		t.Fatalf("foreign source accepted: %x", reply)
	}
}
