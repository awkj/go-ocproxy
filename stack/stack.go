package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type NetStack struct {
	Stack        *stack.Stack
	Link         *channel.Endpoint
	TCPKeepalive time.Duration
}

func NewNetStack(ipAddr string, mtu uint32) (*NetStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	link := channel.New(1024, mtu, "")
	if err := s.CreateNIC(1, link); err != nil {
		return nil, fmt.Errorf("create NIC failed: %v", err)
	}

	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", ipAddr)
	}
	addr := tcpip.AddrFrom4([4]byte(ip[:4]))

	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address failed: %v", err)
	}

	subnet, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	s.SetRouteTable([]tcpip.Route{{Destination: subnet, NIC: 1}})

	return &NetStack{Stack: s, Link: link}, nil
}

func (ns *NetStack) DialTCP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	if ns.TCPKeepalive <= 0 {
		return gonet.DialTCPWithBind(ctx, ns.Stack, tcpip.FullAddress{}, *addr, ipv4.ProtocolNumber)
	}

	var wq waiter.Queue
	ep, tcpErr := ns.Stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}

	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(ns.TCPKeepalive)
	ep.SetSockOpt(&idle)
	intvl := tcpip.KeepaliveIntervalOption(ns.TCPKeepalive)
	ep.SetSockOpt(&intvl)

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		ep.Close()
		return nil, ctx.Err()
	default:
	}

	tcpErr = ep.Connect(*addr)
	if _, ok := tcpErr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}
		tcpErr = ep.LastError()
	}
	if tcpErr != nil {
		ep.Close()
		return nil, errors.New(tcpErr.String())
	}

	return gonet.NewTCPConn(&wq, ep), nil
}

func (ns *NetStack) DialUDP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	return gonet.DialUDP(ns.Stack, &tcpip.FullAddress{}, addr, ipv4.ProtocolNumber)
}

// Run 在 VPN 管道上运行 gVisor 网络栈。
//
// VPNFD 是 AF_UNIX SOCK_DGRAM（见 openconnect tun.c: socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)）。
// 每次 read() 返回一个完整 IP 包；buffer 比 datagram 小则多余部分被内核丢弃。
// 必须一次 Read 拿完整个包，禁止分次读。
func (ns *NetStack) Run(ctx context.Context, input *os.File, output *os.File) error {
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	// net.FileConn 将 fd 正确注册到 Go poller，使 SetReadDeadline 可靠工作。
	// 注意：FileConn 会 dup fd，需单独关闭。
	inputConn, err := net.FileConn(input)
	if err != nil {
		return fmt.Errorf("convert input to conn: %w", err)
	}
	defer inputConn.Close()

	go func() {
		<-innerCtx.Done()
		inputConn.SetReadDeadline(time.Now())
	}()

	rawOutput, err := output.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw output conn: %w", err)
	}

	// Outbound: gVisor -> VPN
	go func() {
		defer cancel()
		for {
			pkt := ns.Link.ReadContext(innerCtx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			_, err := output.Write(buf.Flatten())
			buf.Release()
			if err == nil {
				continue
			}
			if isFatalWriteErr(err) {
				log.Printf("[stack] outbound write fatal, exiting: %v", err)
				errCh <- fmt.Errorf("outbound write fatal: %w", err)
				return
			}
			log.Printf("[stack] outbound write transient (dropping 1 pkt): %v", err)
		}
	}()

	// Health check: 每秒 0 字节 write 探测 VPN 是否存活
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-innerCtx.Done():
				return
			case <-ticker.C:
				var probeErr error
				rawOutput.Control(func(fd uintptr) {
					// getpeername 最可靠：对端关闭后返回 ENOTCONN。
					// write 探测在不同平台行为不一致（macOS: ECONNRESET/EDESTADDRREQ,
					// Linux: ECONNREFUSED/EPIPE），且 0 字节 write 在部分平台无效。
					_, probeErr = syscall.Getpeername(int(fd))
				})
				if probeErr == nil {
					continue
				}
				if probeErr == syscall.ENOTCONN || probeErr == syscall.ECONNREFUSED || probeErr == syscall.EBADF {
					log.Printf("[health] vpn health check failed: %v", probeErr)
					errCh <- fmt.Errorf("vpn health check failed: %w", probeErr)
					cancel()
					return
				}
			}
		}
	}()

	// Inbound: VPN -> gVisor
	pktBuf := make([]byte, 65535)
	for {
		n, err := inputConn.Read(pktBuf)
		if err != nil {
			cancel()
			select {
			case outErr := <-errCh:
				return outErr
			default:
				return err
			}
		}
		if n < 20 {
			continue
		}
		data := make([]byte, n)
		copy(data, pktBuf[:n])
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		ns.Link.InjectInbound(ipv4.ProtocolNumber, pk)
	}
}

func isFatalWriteErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed) {
		return true
	}
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.EBADF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENOTCONN) ||
		errors.Is(err, syscall.EDESTADDRREQ)
}
