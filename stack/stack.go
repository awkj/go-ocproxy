package stack

import (
	"bytes"
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
	if e := ep.SetSockOpt(&idle); e != nil {
		log.Printf("[stack] set keepalive idle failed: %v", e)
	}
	intvl := tcpip.KeepaliveIntervalOption(ns.TCPKeepalive)
	if e := ep.SetSockOpt(&intvl); e != nil {
		log.Printf("[stack] set keepalive interval failed: %v", e)
	}

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

	// context.AfterFunc (Go 1.21) 替代专门起一个 goroutine 等 ctx.Done。
	// 行为等价但少一条 goroutine，且 stop() 能保证函数最多执行一次。
	stopDeadline := context.AfterFunc(innerCtx, func() {
		inputConn.SetReadDeadline(time.Now())
	})
	defer stopDeadline()

	rawOutput, err := output.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw output conn: %w", err)
	}

	// Outbound: gVisor -> VPN
	go func() {
		defer cancel()

		// transient 错误（EAGAIN / ENOBUFS 等）按秒聚合：避免 VPN 抖动时每丢一个
		// 包打一行日志把屏幕刷爆。这里把计数和上次打印时间放在循环本地变量里，
		// 全部由本 goroutine 读写，无数据竞争。
		var droppedSinceLast int
		var lastDropErr error
		lastLogAt := time.Now()

		for {
			// channel.Endpoint.ReadContext 返回的 *PacketBuffer 引用计数 = 1，
			// 调用方持有这一份引用，必须 DecRef 释放。否则每出一个包就泄漏一个
			// PacketBuffer 池里的槽位，长跑高吞吐场景会吃光内存。
			//
			// 注意：buf.Release() 释放的是 ToBuffer() 返回的临时副本，跟 pkt 本体
			// 的引用计数完全是两码事，不能混淆。
			pkt := ns.Link.ReadContext(innerCtx)
			if pkt == nil {
				// 退出前若还有累计的丢包，flush 一行日志免得静默丢失信息
				if droppedSinceLast > 0 {
					log.Printf("[stack] outbound dropped %d pkt before exit (last err: %v)",
						droppedSinceLast, lastDropErr)
				}
				return
			}
			buf := pkt.ToBuffer()
			_, err := output.Write(buf.Flatten())
			buf.Release()
			pkt.DecRef()

			if err == nil {
				continue
			}
			if isFatalWriteErr(err) {
				log.Printf("[stack] outbound write fatal, exiting: %v", err)
				errCh <- fmt.Errorf("outbound write fatal: %w", err)
				return
			}
			// transient：累计计数；每秒最多打一行
			droppedSinceLast++
			lastDropErr = err
			if time.Since(lastLogAt) >= time.Second {
				log.Printf("[stack] outbound dropped %d pkt in last %v (last err: %v)",
					droppedSinceLast, time.Since(lastLogAt).Round(time.Millisecond), lastDropErr)
				droppedSinceLast = 0
				lastDropErr = nil
				lastLogAt = time.Now()
			}
		}
	}()

	// 健康检查：每秒探测 VPN 对端是否还在。
	//
	// 为什么需要：AF_UNIX SOCK_DGRAM 是数据报，没有 TCP 那种 EOF 概念——对端
	// close 之后，本端的 Read 不一定立刻返回错误（macOS 上实测会一直阻塞），
	// inbound 那条退出路径不可靠。所以必须有一个独立 goroutine 主动探。
	//
	// 探测手段为什么是 getpeername 而不是 write：
	//   - 0 字节 write 在某些平台是 no-op，探不出来
	//   - 真正发探测包又会污染 VPN 流量
	//   - getpeername 在 macOS 上对 socketpair 派生的 SOCK_DGRAM，对端关闭后
	//     会返回 ENOTCONN（已通过 TestRunHealthCheckDetectsDeadVPN 验证）
	//
	// 局限：Linux 上 getpeername 的行为可能不一致（不同内核版本）；本项目
	// 只跑在 macOS 上（D-Bar 是 macOS 菜单栏 app），暂不处理。
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
					_, probeErr = syscall.Getpeername(int(fd))
				})
				if probeErr == nil {
					continue
				}
				if errors.Is(probeErr, syscall.ENOTCONN) ||
					errors.Is(probeErr, syscall.ECONNREFUSED) ||
					errors.Is(probeErr, syscall.EBADF) {
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
		// 只接收 IPv4。VPN 偶发的 IPv6/其他协议族包丢弃，避免给只注册了 ipv4
		// 协议的 stack 喂错版本的报文，省掉一次无效 InjectInbound 的 alloc/解析。
		if pktBuf[0]>>4 != 4 {
			continue
		}
		data := bytes.Clone(pktBuf[:n])
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		ns.Link.InjectInbound(ipv4.ProtocolNumber, pk)
		// NewPacketBuffer 返回时引用计数 = 1（调用方持有）。InjectInbound 内部
		// 会自己 IncRef 把包交给协议栈处理直到完成；调用方仍要 DecRef 自己那
		// 一份初始引用，否则入站每个包都会泄漏一个 PacketBuffer 池槽位。
		// 入站吞吐通常远大于出站（下载场景），这条泄漏比出站更致命。
		pk.DecRef()
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
