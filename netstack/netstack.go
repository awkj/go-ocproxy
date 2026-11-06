package netstack

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
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
	HasIPv6      bool
}

func New(ip4Addr string, mtu uint32, ip6Addr string) (*NetStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocolCUBIC, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})

	link := channel.New(1024, mtu, "")
	if err := s.CreateNIC(1, link); err != nil {
		return nil, fmt.Errorf("create NIC failed: %v", err)
	}

	ip := net.ParseIP(ip4Addr).To4()
	if ip == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", ip4Addr)
	}
	addr := tcpip.AddrFrom4([4]byte(ip[:4]))

	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add IPv4 address failed: %v", err)
	}

	subnet4, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	routes := []tcpip.Route{{Destination: subnet4, NIC: 1}}

	hasV6 := false
	if ip6Addr != "" {
		ip6 := net.ParseIP(ip6Addr)
		if ip6 == nil {
			return nil, fmt.Errorf("invalid IPv6 address: %s", ip6Addr)
		}
		if ip6.To4() != nil {
			return nil, fmt.Errorf("expected IPv6 address but got IPv4: %s", ip6Addr)
		}
		addr6 := tcpip.AddrFrom16([16]byte(ip6.To16()))

		if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: addr6.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("add IPv6 address failed: %v", err)
		}

		subnet6, _ := tcpip.NewSubnet(
			tcpip.AddrFrom16([16]byte{}),
			tcpip.MaskFromBytes(make([]byte, 16)),
		)
		routes = append(routes, tcpip.Route{Destination: subnet6, NIC: 1})
		hasV6 = true
	}

	s.SetRouteTable(routes)

	return &NetStack{Stack: s, Link: link, HasIPv6: hasV6}, nil
}

func (ns *NetStack) Close() {
	ns.Stack.Destroy()
}

func protocolForAddr(addr tcpip.Address) tcpip.NetworkProtocolNumber {
	if addr.Len() == 4 {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func (ns *NetStack) DialTCP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	proto := protocolForAddr(addr.Addr)
	if ns.TCPKeepalive <= 0 {
		return gonet.DialTCPWithBind(ctx, ns.Stack, tcpip.FullAddress{}, *addr, proto)
	}

	var wq waiter.Queue
	ep, tcpErr := ns.Stack.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if tcpErr != nil {
		return nil, errors.New(tcpErr.String())
	}

	ep.SocketOptions().SetKeepAlive(true)
	idle := tcpip.KeepaliveIdleOption(ns.TCPKeepalive)
	if e := ep.SetSockOpt(&idle); e != nil {
		log.Printf("[netstack] set keepalive idle failed: %v", e)
	}
	intvl := tcpip.KeepaliveIntervalOption(ns.TCPKeepalive)
	if e := ep.SetSockOpt(&intvl); e != nil {
		log.Printf("[netstack] set keepalive interval failed: %v", e)
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
	return gonet.DialUDP(ns.Stack, &tcpip.FullAddress{}, addr, protocolForAddr(addr.Addr))
}

// Run moves complete IP packets between gVisor and one bidirectional datagram
// tunnel: AF_UNIX SOCK_DGRAM on macOS/Linux or connected loopback UDP on Windows.
func (ns *NetStack) Run(ctx context.Context, tunnel net.Conn) error {
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)

	const bufSize = 1 << 20
	if buffered, ok := tunnel.(interface {
		SetReadBuffer(int) error
		SetWriteBuffer(int) error
	}); ok {
		if err := buffered.SetWriteBuffer(bufSize); err != nil {
			log.Printf("[netstack] set write buffer=%d failed: %v", bufSize, err)
		}
		if err := buffered.SetReadBuffer(bufSize); err != nil {
			log.Printf("[netstack] set read buffer=%d failed: %v", bufSize, err)
		}
	}

	// context.AfterFunc (Go 1.21) 替代专门起一个 goroutine 等 ctx.Done。
	// 行为等价但少一条 goroutine，且 stop() 能保证函数最多执行一次。
	// SetDeadline 同时打断阻塞中的 Read 和 Write。
	stopDeadline := context.AfterFunc(innerCtx, func() {
		tunnel.SetDeadline(time.Now())
	})
	defer stopDeadline()

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

			if err := writeOutboundWithRetry(innerCtx, tunnel, data); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.Canceled) {
					return
				}
				if isFatalWriteErr(err) {
					log.Printf("[netstack] outbound write fatal, exiting: %v", err)
					errCh <- fmt.Errorf("outbound write fatal: %w", err)
					return
				}
				// 非 fatal 但重试上限耗尽：丢这一个包，不退出。每秒最多打一行。
				transientSinceLast++
				lastTransientErr = err
				if time.Since(lastLogAt) >= time.Second {
					log.Printf("[netstack] outbound dropped %d pkt in last %v after retries (last err: %v)",
						transientSinceLast, time.Since(lastLogAt).Round(time.Millisecond), lastTransientErr)
					transientSinceLast = 0
					lastTransientErr = nil
					lastLogAt = time.Now()
				}
			}
		}
	}()

	// macOS inspects its AF_UNIX peer; Linux monitors the OpenConnect process;
	// Windows UDP relies on the external helper's process supervision.
	go func() {
		if err := monitorTunnel(innerCtx, tunnel); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[health] vpn health check failed: %v", err)
			errCh <- fmt.Errorf("vpn health check failed: %w", err)
			cancel()
		}
	}()

	// Inbound: VPN -> gVisor
	pktBuf := make([]byte, 65535)
	for {
		n, err := tunnel.Read(pktBuf)
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
		var proto tcpip.NetworkProtocolNumber
		switch pktBuf[0] >> 4 {
		case 4:
			proto = ipv4.ProtocolNumber
		case 6:
			proto = ipv6.ProtocolNumber
		default:
			continue
		}
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{
			// MakeWithData copies synchronously into gVisor-owned storage.
			Payload: buffer.MakeWithData(pktBuf[:n]),
		})
		ns.Link.InjectInbound(proto, pk)
		// NewPacketBuffer returns one caller-owned reference. InjectInbound is
		// synchronous and does not retain another reference.
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
