package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awkj/go-ocproxy/stack"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const (
	dnsCacheMinTTL          = 30 * time.Second
	dnsCacheMaxTTL          = 1 * time.Hour
	dnsCacheFallbackTTL     = 5 * time.Minute
	dnsCacheNegativeTTL     = 5 * time.Second // 解析失败的负缓存 TTL（短，避免 stale）
	dnsCacheMaxSize         = 512
	dnsCacheCleanupInterval = 60 * time.Second
	dnsUDPTimeout           = 2 * time.Second
	dnsTCPTimeout           = 3 * time.Second
	dnsMaxAttempts          = 3

	socksHandshakeTimeout = 30 * time.Second
	socksDialTimeout      = 15 * time.Second
	maxConnections        = 1024

	socksVer5       = 0x05
	socksCmdConnect = 0x01
	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04
	socksRepOK      = 0x00
	// socksRepGenFail = 0x01 — RFC 1928 通用失败码。SPEC SK-LIMIT-1 提到
	// 「连接达上限回复 REP=0x01」，当前实现在 Accept 后直接 close（更省
	// 资源，但跟 SPEC 不严格一致）。如未来收紧到完整握手 + 拒绝，再启用。
	socksRepHostUnrch  = 0x04
	socksRepCmdNotSupp = 0x07
	socksRepAddrNotSup = 0x08
	socksNoAcceptable  = 0xFF
)

// errDNSRcode 标记 DNS 服务器明确给出非 0 的 rcode（NXDOMAIN/SERVFAIL/REFUSED 等）。
// 这种回复表示服务器已经"作出决定"，跨服务器或重试同一服务器拿到不同结果的概率极低，
// queryDNS 检测到后直接 fail-fast，避免浪费 dnsMaxAttempts 个 RTT。
var errDNSRcode = errors.New("dns rcode")

// ---------------------------------------------------------------------------
// Stats — 运行时统计
// ---------------------------------------------------------------------------

type Stats struct {
	ActiveConns  atomic.Int64
	MaxConns     atomic.Int64
	TotalConns   atomic.Int64
	BytesIn      atomic.Int64
	BytesOut     atomic.Int64
	DNSCacheHit  atomic.Int64
	DNSCacheMiss atomic.Int64
}

func (s *Stats) connOpened() {
	s.TotalConns.Add(1)
	active := s.ActiveConns.Add(1)
	for {
		cur := s.MaxConns.Load()
		if active <= cur || s.MaxConns.CompareAndSwap(cur, active) {
			break
		}
	}
}

func (s *Stats) connClosed() {
	s.ActiveConns.Add(-1)
}

// ---------------------------------------------------------------------------
// DNS Cache（带容量上限 + 过期清理）
// ---------------------------------------------------------------------------

type dnsCacheEntry struct {
	ip     net.IP // nil 表示负缓存（解析失败）
	expiry time.Time
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

// get 返回 (ip, found, negative)：
//   - found=false：缓存里没有或已过期，调用方需要去查 DNS
//   - found=true, negative=true：负缓存（之前查失败过，短期内别再查）
//   - found=true, negative=false：正常命中，ip 有效
func (c *dnsCache) get(name string) (ip net.IP, found bool, negative bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[name]
	if !ok || time.Now().After(e.expiry) {
		return nil, false, false
	}
	return e.ip, true, e.ip == nil
}

// set 写入正常解析结果。
// 特殊处理：上游返回 TTL=0 表示"明确不要缓存"（多见于内网负载均衡的瞬变 IP），
// 此时我们直接跳过缓存，让下次请求重新解析。这优先于 dnsCacheMinTTL 的 clamp。
func (c *dnsCache) set(name string, ip net.IP, ttl time.Duration) {
	if ttl == 0 {
		return
	}
	ttl = max(ttl, dnsCacheMinTTL)
	ttl = min(ttl, dnsCacheMaxTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[name]; !exists && len(c.entries) >= dnsCacheMaxSize {
		c.evictOldestLocked()
	}
	c.entries[name] = dnsCacheEntry{ip: ip, expiry: time.Now().Add(ttl)}
}

// setNegative 写入负缓存。失败结果以 dnsCacheNegativeTTL 短暂缓存，
// 避免 app 反复请求一个不存在的域名时把每次都打到上游 DNS。
// TTL 故意设得很短（5s），让真域名上线后能很快被发现。
func (c *dnsCache) setNegative(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[name]; !exists && len(c.entries) >= dnsCacheMaxSize {
		c.evictOldestLocked()
	}
	c.entries[name] = dnsCacheEntry{ip: nil, expiry: time.Now().Add(dnsCacheNegativeTTL)}
}

func (c *dnsCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, v := range c.entries {
		if oldestKey == "" || v.expiry.Before(oldestTime) {
			oldestKey = k
			oldestTime = v.expiry
		}
	}
	delete(c.entries, oldestKey)
}

func (c *dnsCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	maps.DeleteFunc(c.entries, func(_ string, v dnsCacheEntry) bool {
		return now.After(v.expiry)
	})
}

func (c *dnsCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

type Server struct {
	ns         *stack.NetStack
	listen     string
	dnsServers []string
	dnsDomain  string
	cache      *dnsCache
	Stats      Stats
	connLimit  chan struct{}
	listener   net.Listener
	wg         sync.WaitGroup
}

func NewServer(ns *stack.NetStack, listen string, dnsServers []string, dnsDomain string) *Server {
	return &Server{
		ns:         ns,
		listen:     listen,
		dnsServers: dnsServers,
		dnsDomain:  dnsDomain,
		cache:      newDNSCache(),
		connLimit:  make(chan struct{}, maxConnections),
	}
}

func (s *Server) Listen() error {
	l, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	s.listener = l
	log.Printf("[socks] listening on %s", s.listen)
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	go s.cacheCleanupLoop(ctx)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		select {
		case s.connLimit <- struct{}{}:
		default:
			log.Printf("[socks] max connections reached (%d), rejecting %s", maxConnections, conn.RemoteAddr())
			conn.Close()
			continue
		}

		s.wg.Go(func() {
			defer func() { <-s.connLimit }()
			// 单条连接 panic 不应该拖垮整个代理进程。本地代理对可用性敏感（同时
			// 服务很多 app 的连接），任何一个客户端触发的异常路径——gVisor 内部
			// panic、SOCKS 报文解析里没覆盖到的边界——都会通过 io.Copy / dial
			// 的调用栈冒泡上来。这里 recover 掉 + 打日志，让其他 N-1 条连接继续。
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[socks] handle panic from %s: %v", conn.RemoteAddr(), r)
					conn.Close()
				}
			}()
			s.handle(conn)
		})
	}
}

func (s *Server) Close(timeout time.Duration) {
	if s.listener != nil {
		s.listener.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Printf("[socks] all connections closed")
	case <-time.After(timeout):
		log.Printf("[socks] shutdown timeout, %d connections still active", s.Stats.ActiveConns.Load())
	}
}

func (s *Server) DumpStats() {
	log.Printf("[stats] connections: active=%d max=%d total=%d dns_cache_size=%d hit=%d miss=%d",
		s.Stats.ActiveConns.Load(),
		s.Stats.MaxConns.Load(),
		s.Stats.TotalConns.Load(),
		s.cache.size(),
		s.Stats.DNSCacheHit.Load(),
		s.Stats.DNSCacheMiss.Load(),
	)
}

func (s *Server) cacheCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(dnsCacheCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cache.evictExpired()
		}
	}
}

// ---------------------------------------------------------------------------
// SOCKS5 handler
// ---------------------------------------------------------------------------

func socksReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVer5, rep, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	start := time.Now()
	remote := conn.RemoteAddr().String()

	s.Stats.connOpened()
	defer s.Stats.connClosed()

	conn.SetDeadline(time.Now().Add(socksHandshakeTimeout))

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

		dnsCtx, dnsCancel := context.WithTimeout(context.Background(), socksDialTimeout)
		ip, err := s.resolve(dnsCtx, host)
		dnsCancel()
		if err != nil {
			log.Printf("[dns] %s lookup failed for %s: %v", remote, host, err)
			socksReply(conn, socksRepHostUnrch)
			return
		}
		targetIP = ip

	case socksAtypIPv6:
		log.Printf("[socks] %s IPv6 address type not supported", remote)
		socksReply(conn, socksRepAddrNotSup)
		return

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

	targetIP4 := targetIP.To4()
	if targetIP4 == nil {
		log.Printf("[socks] %s resolved IP %s is not IPv4", remote, targetIP)
		socksReply(conn, socksRepAddrNotSup)
		return
	}

	// --- 3. Connect via NetStack ---
	log.Printf("[socks] %s -> %s (%s):%d", remote, host, targetIP4, port)

	// 在 dial 前清掉 conn 的握手 deadline。理由：
	//   - 握手阶段 30s deadline 是绝对时间。dial 自己有 socksDialTimeout=15s。
	//   - 如果握手已用 ~16s + dial 用了 ~14s，握手 deadline 触发，后续给客户端写
	//     reply 的时候 conn 已经处于 deadline 过期状态，Write 立刻失败。
	//   - 这条连接的"防 slowloris"职责到此结束（已读到完整 request），后面 dial
	//     和数据转发都有自己的时限或对端控制，不再需要 conn 级别 deadline。
	conn.SetDeadline(time.Time{})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), socksDialTimeout)
	defer dialCancel()

	addr := tcpip.AddrFrom4([4]byte(targetIP4[:4]))
	tunnel, err := s.ns.DialTCP(dialCtx, &tcpip.FullAddress{Addr: addr, Port: port})
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
	//
	// 字节计数用 atomic 而非局部变量：原本 `var bytesIn, bytesOut int64` + 子
	// goroutine 写、main goroutine 读，虽然靠 channel 提供了 happens-before，
	// 但用 -race 仍可能误报，且语义脆弱。换 atomic.Int64 一劳永逸。
	//
	// sync.WaitGroup.Go (Go 1.25) 替代 errCh + 两次 <-errCh 的样板。
	var bytesIn, bytesOut atomic.Int64
	var wg sync.WaitGroup
	wg.Go(func() {
		n, _ := io.Copy(tunnel, conn)
		bytesIn.Store(n)
		if cw, ok := tunnel.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	})
	wg.Go(func() {
		n, _ := io.Copy(conn, tunnel)
		bytesOut.Store(n)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	})
	wg.Wait()

	bin, bout := bytesIn.Load(), bytesOut.Load()
	s.Stats.BytesIn.Add(bin)
	s.Stats.BytesOut.Add(bout)

	dur := time.Since(start).Round(time.Millisecond)
	log.Printf("[socks] %s -> %s closed, duration=%s in=%d out=%d", remote, host, dur, bin, bout)
}

// ---------------------------------------------------------------------------
// DNS 解析（支持域名后缀两阶段解析）
// ---------------------------------------------------------------------------

func (s *Server) resolve(ctx context.Context, name string) (net.IP, error) {
	// 缓存查询有三种结果：命中正常 / 命中负缓存（最近失败过）/ 未命中
	if ip, found, negative := s.cache.get(name); found {
		s.Stats.DNSCacheHit.Add(1)
		if negative {
			// 短期内已经查过且失败过，直接返回失败避免反复打上游 DNS
			return nil, fmt.Errorf("negative cache hit for %s", name)
		}
		return ip, nil
	}
	s.Stats.DNSCacheMiss.Add(1)

	var ip net.IP
	var ttl time.Duration
	var err error

	switch {
	case strings.Contains(name, "."):
		// FQDN：只查原始名称（SPEC DNS-SUFFIX-3）。例如 www.google.com 不会
		// 衍生出 www.google.com.corp.example.com 这种没意义的查询。
		ip, ttl, err = s.queryDNS(ctx, name)
	case s.dnsDomain != "":
		// 裸名 + 配置了后缀：先查原始（SPEC DNS-SUFFIX-2），失败再带后缀。
		// 顺序顺着 SPEC：万一裸名本身在公网就有解析，优先用它。
		ip, ttl, err = s.queryDNS(ctx, name)
		if err != nil {
			ip, ttl, err = s.queryDNS(ctx, name+"."+s.dnsDomain)
		}
	default:
		// 裸名 + 无后缀配置：直接查
		ip, ttl, err = s.queryDNS(ctx, name)
	}

	if err != nil {
		// 写入负缓存：5s 内同一域名再来也直接失败，不打 DNS
		s.cache.setNegative(name)
		return nil, err
	}
	s.cache.set(name, ip, ttl)
	return ip, nil
}

func (s *Server) queryDNS(ctx context.Context, name string) (net.IP, time.Duration, error) {
	if len(s.dnsServers) == 0 {
		ips, err := net.LookupIP(name)
		if err != nil {
			return nil, 0, err
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				return v4, dnsCacheFallbackTTL, nil
			}
		}
		return nil, 0, fmt.Errorf("no IPv4 address for %s", name)
	}

	start := rand.IntN(len(s.dnsServers))
	var lastErr error
	for i := range dnsMaxAttempts {
		server := s.dnsServers[(start+i)%len(s.dnsServers)]
		ip, ttl, err := s.dnsQuery(ctx, name, server)
		if err == nil && ip != nil {
			return ip, ttl, nil
		}
		// rcode 类错误（NXDOMAIN/SERVFAIL/REFUSED）是服务器的明确判定，
		// 跨服务器或重试拿到不同结果概率极低，直接返回避免浪费 RTT。
		if errors.Is(err, errDNSRcode) {
			return nil, 0, err
		}
		// 兜底：dnsQuery 返回 (nil, 0, nil) 不应该发生，但若发生不能让 lastErr
		// 一直是 nil 而 fall through 到 `return nil, 0, nil`——上层会把 nil IP
		// 当成正常结果写入缓存，污染后续查询。
		if err == nil {
			err = fmt.Errorf("dns query for %q returned no result", name)
		}
		lastErr = err
	}
	return nil, 0, lastErr
}

// ---------------------------------------------------------------------------
// DNS 协议实现
// ---------------------------------------------------------------------------

func (s *Server) dnsQuery(ctx context.Context, name, server string) (net.IP, time.Duration, error) {
	dnsAddr := server
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}
	host, portStr, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid dns server %q: %w", server, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid dns server port %q: %w", portStr, err)
	}
	parsed := net.ParseIP(host).To4()
	if parsed == nil {
		return nil, 0, &net.AddrError{Err: "invalid dns server", Addr: host}
	}
	addr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte(parsed[:4])),
		Port: uint16(port),
	}

	id := uint16(rand.Uint32())
	query, err := buildDNSQuery(name, id)
	if err != nil {
		return nil, 0, err
	}

	resp, truncated, udpErr := s.queryUDP(ctx, addr, query)
	if udpErr == nil && !truncated {
		return parseDNSResponse(resp, id)
	}
	resp, tcpErr := s.queryTCP(ctx, addr, query)
	if tcpErr != nil {
		if udpErr != nil {
			// errors.Join (Go 1.20)：保留双侧 error，调用方可用 errors.Is
			// 穿透到具体 syscall errno（比如 errors.Is(err, context.DeadlineExceeded)）。
			return nil, 0, errors.Join(
				fmt.Errorf("udp: %w", udpErr),
				fmt.Errorf("tcp: %w", tcpErr),
			)
		}
		return nil, 0, tcpErr
	}
	return parseDNSResponse(resp, id)
}

func (s *Server) queryUDP(ctx context.Context, addr *tcpip.FullAddress, query []byte) ([]byte, bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dnsUDPTimeout)
	defer cancel()
	conn, err := s.ns.DialUDP(dialCtx, addr)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsUDPTimeout))

	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 1232)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, fmt.Errorf("udp dns response too short: %d bytes", n)
	}
	truncated := (buf[2] & 0x02) != 0
	return buf[:n], truncated, nil
}

func (s *Server) queryTCP(ctx context.Context, addr *tcpip.FullAddress, query []byte) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dnsTCPTimeout)
	defer cancel()
	conn, err := s.ns.DialTCP(dialCtx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(dnsTCPTimeout))

	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(query)))
	if _, err := conn.Write(lenPrefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	var respLenBuf [2]byte
	if _, err := io.ReadFull(conn, respLenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])
	if respLen == 0 {
		return nil, fmt.Errorf("tcp dns zero-length response")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// EDNS0 UDP payload size：告诉 DNS 服务器我们能收多大的 UDP 响应。
// 1232 = 1280 (IPv6 最小 MTU) - 40 (IPv6 头) - 8 (UDP 头)，是 DNS Flag Day
// 推荐值，能避免 IP 分片同时容纳绝大多数响应。
const ednsUDPSize = 1232

// buildDNSQuery 构造一个带 EDNS0 OPT 的 A 记录查询。
//
// 实现细节用 golang.org/x/net/dns/dnsmessage 的 Builder：标准库附属包，
// 内部全是 append 不依赖反射，等价于手写但少了 ~80 行 off+10 之类的偏移量
// 算术，封掉了一整类 buffer overrun bug。
func buildDNSQuery(name string, id uint16) ([]byte, error) {
	if name == "" {
		return nil, fmt.Errorf("empty dns name")
	}
	// dnsmessage.NewName 要求以 "." 结尾的 FQDN
	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	qname, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("invalid dns name %q: %w", name, err)
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, 64), dnsmessage.Header{
		ID:               id,
		RecursionDesired: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  qname,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	// EDNS0 OPT pseudo-RR (RFC 6891)：不声明时 UDP 响应封顶 512 字节，超过会
	// TC=1 强制 TCP 重查（多一个 RTT）。声明后服务器可以直接回 1232 字节。
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(ednsUDPSize, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// parseDNSResponse 解析响应，返回第一个 A 记录的 IP + TTL。
// 用 dnsmessage.Parser 取代手写状态机：CNAME 链、name compression、
// answer section 边界全由库处理。
func parseDNSResponse(resp []byte, expectedID uint16) (net.IP, time.Duration, error) {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("parse dns header: %w", err)
	}
	if h.ID != expectedID {
		return nil, 0, fmt.Errorf("dns id mismatch")
	}
	if h.RCode != dnsmessage.RCodeSuccess {
		// errDNSRcode 让 queryDNS 能 errors.Is 检测出来 fail-fast。
		return nil, 0, fmt.Errorf("%w %d", errDNSRcode, int(h.RCode))
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, 0, fmt.Errorf("skip questions: %w", err)
	}
	for {
		ah, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("parse answer header: %w", err)
		}
		if ah.Type != dnsmessage.TypeA {
			// CNAME / AAAA / 其他记录跳过。Parser 知道每种 RR 的边界。
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, fmt.Errorf("skip answer: %w", err)
			}
			continue
		}
		a, err := p.AResource()
		if err != nil {
			return nil, 0, fmt.Errorf("parse A: %w", err)
		}
		ip := net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3])
		return ip, time.Duration(ah.TTL) * time.Second, nil
	}
	return nil, 0, fmt.Errorf("no A record in dns response")
}
