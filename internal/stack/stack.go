package stack

import (
	"context"
	"fmt"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type NetStack struct {
	Stack *stack.Stack
	Link  *channel.Endpoint
}

func NewNetStack(ipAddr string, mtu uint32) (*NetStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	link := channel.New(256, mtu, "")
	if err := s.CreateNIC(1, link); err != nil {
		return nil, fmt.Errorf("create NIC failed: %v", err)
	}

	ip := net.ParseIP(ipAddr).To4()
	addr := tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address failed: %v", err)
	}

	// 设置默认路由
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	return &NetStack{
		Stack: s,
		Link:  link,
	}, nil
}

func (ns *NetStack) DialTCP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	return gonet.DialTCPWithBind(ctx, ns.Stack, tcpip.FullAddress{}, *addr, ipv4.ProtocolNumber)
}

func (ns *NetStack) DialUDP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	return gonet.DialUDP(ns.Stack, &tcpip.FullAddress{}, addr, ipv4.ProtocolNumber)
}

func (ns *NetStack) Run(input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle output from stack to stdout (VPN)
	go func() {
		for {
			pkt := ns.Link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			
			// 写入数据包内容到 stdout
			buf := pkt.ToBuffer()
			output.Write(buf.Flatten())
			buf.Release()
		}
	}()

	// Handle input from stdin (VPN) to stack
	for {
		header := make([]byte, 20)
		_, err := io.ReadFull(input, header)
		if err != nil {
			return err
		}

		totalLen := int(header[2])<<8 | int(header[3])
		if totalLen < 20 || totalLen > 65535 {
			continue
		}

		payload := make([]byte, totalLen-20)
		_, err = io.ReadFull(input, payload)
		if err != nil {
			return err
		}

		fullPacket := append(header, payload...)
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(fullPacket),
		})
		ns.Link.InjectInbound(ipv4.ProtocolNumber, pk)
	}
}
