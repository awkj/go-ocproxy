package proxy

import (
	"context"
	"errors"
	"log"
	"maps"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/awkj/go-ocproxy/netstack"
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

	socksVer5          = 0x05
	socksCmdConnect    = 0x01
	socksAtypIPv4      = 0x01
	socksAtypDomain    = 0x03
	socksAtypIPv6      = 0x04
	socksRepOK         = 0x00
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
	ns         *netstack.NetStack
	listen     string
	dnsServers []string
	dnsDomain  string
	cache      *dnsCache
	dnsLookups dnsLookupGroup
	Stats      Stats
	connLimit  chan struct{}
	listener   net.Listener
	wg         sync.WaitGroup
}

func NewServer(ns *netstack.NetStack, listen string, dnsServers []string, dnsDomain string) *Server {
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
			s.handle(ctx, conn)
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
