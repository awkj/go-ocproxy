package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// bufferedConn exposes bytes already inspected by protocol sniffing to all
// subsequent reads.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// ---------------------------------------------------------------------------
// SOCKS5 handler
// ---------------------------------------------------------------------------

func socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVer5, rep, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func (s *Server) handle(ctx context.Context, rawConn net.Conn) {
	defer rawConn.Close()
	stopCancel := context.AfterFunc(ctx, func() { rawConn.SetDeadline(time.Now()) })
	defer stopCancel()

	s.Stats.connOpened()
	defer s.Stats.connClosed()

	rawConn.SetDeadline(time.Now().Add(socksHandshakeTimeout))

	br := bufio.NewReader(rawConn)
	first, err := br.Peek(1)
	if err != nil {
		log.Printf("[proxy] %s peek failed: %v", rawConn.RemoteAddr(), err)
		return
	}
	conn := &bufferedConn{r: br, Conn: rawConn}

	// 嗅探：HTTP 方法首字节必为大写 ASCII 字母（GET/POST/HEAD/CONNECT/PUT/...），
	// 其余一律交给 SOCKS5 处理 —— version 不是 0x05 时 handler 会回 {0x05, 0xFF}。
	if first[0] >= 'A' && first[0] <= 'Z' {
		s.handleHTTP(ctx, conn, br)
	} else {
		s.handleSOCKS5(ctx, conn)
	}
}

func (s *Server) handleSOCKS5(ctx context.Context, conn net.Conn) {
	start := time.Now()
	remote := conn.RemoteAddr().String()

	buf := make([]byte, 1024)

	// --- 1. Auth negotiation ---
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		log.Printf("[socks] %s handshake read failed: %v", remote, err)
		return
	}
	if buf[0] != socksVer5 {
		log.Printf("[socks] %s unsupported SOCKS version: 0x%02x", remote, buf[0])
		conn.Write([]byte{socksVer5, socksNoAcceptable})
		return
	}
	// RFC 1928 §3：客户端发 (VER, NMETHODS, METHODS[NMETHODS])。
	// 我们只支持 NOAUTH (0x00)。严格按 spec：
	//   - 必须读完所有 METHODS 字节，否则后面会把它们当作 request 报文乱解。
	//   - 客户端必须在 METHODS 列表里包含 0x00；没有则回 0xFF 拒绝（spec §3）。
	//   - NMETHODS=0 是非法报文，按拒绝处理。
	nMethods := int(buf[1])
	if nMethods == 0 {
		log.Printf("[socks] %s NMETHODS=0, rejecting", remote)
		conn.Write([]byte{socksVer5, socksNoAcceptable})
		return
	}
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		log.Printf("[socks] %s handshake read methods failed: %v", remote, err)
		return
	}
	if !slices.Contains(buf[:nMethods], byte(0x00)) {
		log.Printf("[socks] %s no acceptable auth method offered: %x", remote, buf[:nMethods])
		conn.Write([]byte{socksVer5, socksNoAcceptable})
		return
	}
	if _, err := conn.Write([]byte{socksVer5, 0x00}); err != nil {
		log.Printf("[socks] %s handshake write failed: %v", remote, err)
		return
	}

	// --- 2. Request ---
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		log.Printf("[socks] %s request read failed: %v", remote, err)
		return
	}
	if buf[1] != socksCmdConnect {
		log.Printf("[socks] %s unsupported command: 0x%02x", remote, buf[1])
		socksReply(conn, socksRepCmdNotSupp)
		return
	}

	var host string
	var targetIP net.IP
	switch buf[3] {
	case socksAtypIPv4:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			log.Printf("[socks] %s read IPv4 addr failed: %v", remote, err)
			return
		}
		targetIP = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		host = targetIP.String()

	case socksAtypDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			log.Printf("[socks] %s read domain length failed: %v", remote, err)
			return
		}
		domainLen := int(buf[0])
		if domainLen == 0 {
			log.Printf("[socks] %s empty domain name, rejecting", remote)
			socksReply(conn, socksRepAddrNotSup)
			return
		}
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			log.Printf("[socks] %s read domain failed: %v", remote, err)
			return
		}
		host = string(buf[:domainLen])

		dnsCtx, dnsCancel := context.WithTimeout(ctx, socksDialTimeout)
		ip, err := s.resolve(dnsCtx, host)
		dnsCancel()
		if err != nil {
			log.Printf("[dns] %s lookup failed for %s: %v", remote, host, err)
			socksReply(conn, socksRepHostUnrch)
			return
		}
		targetIP = ip

	case socksAtypIPv6:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			log.Printf("[socks] %s read IPv6 addr failed: %v", remote, err)
			return
		}
		targetIP = make(net.IP, 16)
		copy(targetIP, buf[:16])
		host = targetIP.String()

	default:
		log.Printf("[socks] %s unknown address type: 0x%02x", remote, buf[3])
		socksReply(conn, socksRepAddrNotSup)
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		log.Printf("[socks] %s read port failed: %v", remote, err)
		return
	}
	port := uint16(buf[0])<<8 | uint16(buf[1])

	if v4 := targetIP.To4(); v4 != nil {
		targetIP = v4
	}

	// --- 3. Connect via NetStack ---
	log.Printf("[socks] %s -> %s (%s):%d", remote, host, targetIP, port)

	// 在 dial 前清掉 conn 的握手 deadline。理由：
	//   - 握手阶段 30s deadline 是绝对时间。dial 自己有 socksDialTimeout=15s。
	//   - 如果握手已用 ~16s + dial 用了 ~14s，握手 deadline 触发，后续给客户端写
	//     reply 的时候 conn 已经处于 deadline 过期状态，Write 立刻失败。
	//   - 这条连接的"防 slowloris"职责到此结束（已读到完整 request），后面 dial
	//     和数据转发都有自己的时限或对端控制，不再需要 conn 级别 deadline。
	conn.SetDeadline(time.Time{})

	dialCtx, dialCancel := context.WithTimeout(ctx, socksDialTimeout)
	defer dialCancel()

	tunnel, err := s.dialNetstack(dialCtx, targetIP, port)
	if err != nil {
		log.Printf("[socks] %s dial %s:%d failed: %v", remote, host, port, err)
		socksReply(conn, socksRepHostUnrch)
		return
	}
	defer tunnel.Close()

	if err := socksReply(conn, socksRepOK); err != nil {
		log.Printf("[socks] %s write connect reply failed: %v", remote, err)
		return
	}

	// --- 4. Bidirectional copy with half-close ---
	bytesIn, bytesOut := bidirectionalCopy(ctx, conn, tunnel)

	s.Stats.BytesIn.Add(bytesIn)
	s.Stats.BytesOut.Add(bytesOut)

	dur := time.Since(start).Round(time.Millisecond)
	log.Printf("[socks] %s -> %s closed, duration=%s in=%d out=%d", remote, host, dur, bytesIn, bytesOut)
}

func (s *Server) dialNetstack(ctx context.Context, ip net.IP, port uint16) (net.Conn, error) {
	var addr tcpip.Address
	if v4 := ip.To4(); v4 != nil {
		addr = tcpip.AddrFrom4([4]byte(v4))
	} else {
		addr = tcpip.AddrFrom16([16]byte(ip.To16()))
	}
	return s.ns.DialTCP(ctx, &tcpip.FullAddress{Addr: addr, Port: port})
}

func (s *Server) resolveAndDial(ctx context.Context, host string, port uint16) (net.Conn, error) {
	var ip net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ip = parsed
	} else {
		resolved, err := s.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		ip = resolved
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return s.dialNetstack(ctx, ip, port)
}

// bidirectionalCopy 在两个连接间双向拷贝，遇到一端 EOF 时半关闭对侧写端。
//
// Each goroutine owns one counter. Wait publishes both results to the caller;
// no per-direction atomic store/load is needed (including under -race).
func bidirectionalCopy(ctx context.Context, client, tunnel net.Conn) (int64, int64) {
	stopCancel := context.AfterFunc(ctx, func() {
		client.SetDeadline(time.Now())
		tunnel.SetDeadline(time.Now())
	})
	defer stopCancel()
	var bytesIn, bytesOut int64
	var wg sync.WaitGroup
	wg.Go(func() {
		n, _ := io.Copy(tunnel, client)
		bytesIn = n
		if cw, ok := tunnel.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	})
	wg.Go(func() {
		n, _ := io.Copy(client, tunnel)
		bytesOut = n
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	})
	wg.Wait()
	return bytesIn, bytesOut
}
