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

	// 调大 VPN socketpair 这一端的 SNDBUF/RCVBUF。
	// 必须在 net.FileConn 之前操作原始 fd：FileConn dup fd 后会把它设成
	// O_NONBLOCK，配合较小的默认 buffer，高吞吐上传时一灌就满直接 EAGAIN。
	// macOS 默认 SO_SNDBUF 对 AF_UNIX SOCK_DGRAM 通常只有 8K 量级，调大到 1MB
	// 大幅减少 net.Conn.Write 因 buffer 满而挂起 goroutine 的概率。
	if rawIn, e := input.SyscallConn(); e == nil {
		const bufSize = 1 << 20 // 1 MiB
		_ = rawIn.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize); err != nil {
				log.Printf("[stack] set SO_SNDBUF=%d failed: %v", bufSize, err)
			}
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, bufSize); err != nil {
				log.Printf("[stack] set SO_RCVBUF=%d failed: %v", bufSize, err)
			}
		})
	}

	// net.FileConn 将 fd 正确注册到 Go poller，使 SetReadDeadline / Write 阻塞
	// 重试可靠工作。注意：FileConn 会 dup fd 并把它设为 O_NONBLOCK，需单独关闭。
	//
	// input 和 output 是 openconnect socketpair 的同一端（同一 *os.File），
	// 共用一个 net.Conn 既读又写即可：net.Conn.Write 在 fd 不可写（EAGAIN）时
	// 会挂起 goroutine 等到可写而不是丢包，这是修复上传卡死的关键——之前用
	// output.Write（裸 *os.File）时，由于 FileConn dup 共享了 file description，
	// 原 fd 也变成非阻塞，buffer 满直接 EAGAIN，包被静默丢弃。
	vpnConn, err := net.FileConn(input)
	if err != nil {
		return fmt.Errorf("convert vpn fd to conn: %w", err)
	}
	defer vpnConn.Close()

	// context.AfterFunc (Go 1.21) 替代专门起一个 goroutine 等 ctx.Done。
	// 行为等价但少一条 goroutine，且 stop() 能保证函数最多执行一次。
	// SetDeadline 同时打断阻塞中的 Read 和 Write。
	stopDeadline := context.AfterFunc(innerCtx, func() {
		vpnConn.SetDeadline(time.Now())
	})
	defer stopDeadline()

	// 健康检查仍用原 *os.File 的 SyscallConn 做 getpeername 探测；fd 与 vpnConn
	// 共享底层 file description，对原 fd 调 syscall 等价于对 vpnConn 调。
	rawOutput, err := output.SyscallConn()
	if err != nil {
		return fmt.Errorf("get raw output conn: %w", err)
	}

	// Outbound: gVisor -> VPN
	//
	// 错误处理策略：
	//   - fatal（EPIPE/ECONNRESET/EBADF/ENOTCONN 等连接死亡）→ 退出 goroutine
	//   - ctx 取消触发的 ErrDeadlineExceeded → 静默退出
	//   - transient（主要是 ENOBUFS：macOS AF_UNIX SOCK_DGRAM 在高流量下系统
	//     mbuf 池暂时耗尽）→ backoff 重试同一个包。Go runtime poller 会自动
	//     重试 EAGAIN，但不会重试 ENOBUFS，必须我们自己退避后重试。
	//
	// 不能像旧版本那样静默丢包：丢包会触发 gVisor TCP 重传，但底层 buffer
	// 仍然紧张，重传也丢，连接事实停滞——这正是上传卡死的根因。
	go func() {
		defer cancel()

		var transientSinceLast int
		var lastTransientErr error
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
				return
			}
			buf := pkt.ToBuffer()
			data := buf.Flatten()
			buf.Release()
			pkt.DecRef()

			if err := writeOutboundWithRetry(innerCtx, vpnConn, data); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
					return
				}
				if isFatalWriteErr(err) {
					log.Printf("[stack] outbound write fatal, exiting: %v", err)
					errCh <- fmt.Errorf("outbound write fatal: %w", err)
					return
				}
				// 非 fatal 但重试上限耗尽：丢这一个包，不退出。每秒最多打一行。
				transientSinceLast++
				lastTransientErr = err
				if time.Since(lastLogAt) >= time.Second {
					log.Printf("[stack] outbound dropped %d pkt in last %v after retries (last err: %v)",
						transientSinceLast, time.Since(lastLogAt).Round(time.Millisecond), lastTransientErr)
					transientSinceLast = 0
					lastTransientErr = nil
					lastLogAt = time.Now()
				}
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
		n, err := vpnConn.Read(pktBuf)
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

// writeOutboundWithRetry 写一个 IP 包到 VPN 连接，遇到 transient 错误
// （非 fatal 且非 ctx 取消，主要是 ENOBUFS）时按指数退避重试。
//
// 为什么需要：macOS AF_UNIX SOCK_DGRAM 在大流量上传时，系统 mbuf 池可能
// 暂时耗尽，sendto() 返回 ENOBUFS。Go runtime poller 会自动重试 EAGAIN
// 但不会重试 ENOBUFS——它会原样返回这个错误。如果调用方把 ENOBUFS 当
// fatal 退出，整条 SOCKS5 服务就会在大文件上传后挂掉；如果当 transient
// 静默丢包，又会触发 TCP 反复重传陷入卡死。正确的处理是短暂退避后重试
// 同一个包，给系统一点时间释放 mbuf。
//
// 重试策略：1ms / 2ms / 4ms / ... 上限 32ms，最多 10 次（累计约 191ms）。
// 超过仍失败则把错误返回给调用方，由调用方决定丢包还是退出。
//
// 这几个参数提成包级变量是为了测试能临时覆盖，免得单测真睡 200ms。
var (
	outboundMaxRetries   = 10
	outboundInitialDelay = 1 * time.Millisecond
	outboundMaxDelay     = 32 * time.Millisecond
)

func writeOutboundWithRetry(ctx context.Context, conn net.Conn, data []byte) error {
	delay := outboundInitialDelay

	var err error
	for range outboundMaxRetries {
		_, err = conn.Write(data)
		if err == nil {
			return nil
		}
		if isFatalWriteErr(err) || errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}
		// transient（ENOBUFS 等）：退避重试
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay < outboundMaxDelay {
			delay *= 2
			if delay > outboundMaxDelay {
				delay = outboundMaxDelay
			}
		}
	}
	return err
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
