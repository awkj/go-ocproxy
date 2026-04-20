package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"maps"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/doctor/go-ocproxy/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const (
	dnsCacheMinTTL          = 30 * time.Second
	dnsCacheMaxTTL          = 1 * time.Hour
	dnsCacheFallbackTTL     = 5 * time.Minute
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
	socksRepGenFail    = 0x01
	socksRepHostUnrch  = 0x04
	socksRepCmdNotSupp = 0x07
	socksRepAddrNotSup = 0x08
	socksNoAcceptable  = 0xFF
)

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
	ip     net.IP
	expiry time.Time
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) get(name string) (net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[name]
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.ip, true
}

func (c *dnsCache) set(name string, ip net.IP, ttl time.Duration) {
	ttl = max(ttl, dnsCacheMinTTL)
	ttl = min(ttl, dnsCacheMaxTTL)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[name]; !exists && len(c.entries) >= dnsCacheMaxSize {
		c.evictOldestLocked()
	}
	c.entries[name] = dnsCacheEntry{ip: ip, expiry: time.Now().Add(ttl)}
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

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.connLimit }()
			s.handle(conn)
		}()
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
	if nMethods := int(buf[1]); nMethods > 0 {
		if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
			log.Printf("[socks] %s handshake read methods failed: %v", remote, err)
			return
		}
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

	conn.SetDeadline(time.Time{})

	// --- 4. Bidirectional copy with half-close ---
	var bytesIn, bytesOut int64
	errCh := make(chan error, 2)

	go func() {
		n, err := io.Copy(tunnel, conn)
		bytesIn = n
		if cw, ok := tunnel.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errCh <- err
	}()
	go func() {
		n, err := io.Copy(conn, tunnel)
		bytesOut = n
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		errCh <- err
	}()
	<-errCh
	<-errCh

	s.Stats.BytesIn.Add(bytesIn)
	s.Stats.BytesOut.Add(bytesOut)

	dur := time.Since(start).Round(time.Millisecond)
	log.Printf("[socks] %s -> %s closed, duration=%s in=%d out=%d", remote, host, dur, bytesIn, bytesOut)
}

// ---------------------------------------------------------------------------
// DNS 解析（支持域名后缀两阶段解析）
// ---------------------------------------------------------------------------

func (s *Server) resolve(ctx context.Context, name string) (net.IP, error) {
	if ip, ok := s.cache.get(name); ok {
		s.Stats.DNSCacheHit.Add(1)
		return ip, nil
	}
	s.Stats.DNSCacheMiss.Add(1)

	var ip net.IP
	var ttl time.Duration
	var err error

	if strings.Contains(name, ".") {
		ip, ttl, err = s.queryDNS(ctx, name)
		if err != nil && s.dnsDomain != "" {
			ip, ttl, err = s.queryDNS(ctx, name+"."+s.dnsDomain)
		}
	} else {
		if s.dnsDomain != "" {
			ip, ttl, err = s.queryDNS(ctx, name+"."+s.dnsDomain)
		}
		if s.dnsDomain == "" || err != nil {
			ip, ttl, err = s.queryDNS(ctx, name)
		}
	}

	if err != nil {
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
	host, portStr, _ := net.SplitHostPort(dnsAddr)
	port, _ := strconv.Atoi(portStr)
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
			return nil, 0, fmt.Errorf("udp: %v; tcp: %v", udpErr, tcpErr)
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

func buildDNSQuery(name string, id uint16) ([]byte, error) {
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	buf = append(buf, 0, 1, 0, 1)
	return buf, nil
}

func parseDNSResponse(resp []byte, expectedID uint16) (net.IP, time.Duration, error) {
	if len(resp) < 12 {
		return nil, 0, fmt.Errorf("dns response too short: %d", len(resp))
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectedID {
		return nil, 0, fmt.Errorf("dns id mismatch")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if rcode := flags & 0x0F; rcode != 0 {
		return nil, 0, fmt.Errorf("dns rcode %d", rcode)
	}
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	anCount := binary.BigEndian.Uint16(resp[6:8])

	off := 12
	for range qdCount {
		newOff, err := skipDNSName(resp, off)
		if err != nil {
			return nil, 0, err
		}
		off = newOff + 4
		if off > len(resp) {
			return nil, 0, fmt.Errorf("dns question truncated")
		}
	}
	for range anCount {
		newOff, err := skipDNSName(resp, off)
		if err != nil {
			return nil, 0, err
		}
		off = newOff
		if off+10 > len(resp) {
			return nil, 0, fmt.Errorf("dns answer header truncated")
		}
		rtype := binary.BigEndian.Uint16(resp[off : off+2])
		ttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
		rdLen := binary.BigEndian.Uint16(resp[off+8 : off+10])
		off += 10
		if off+int(rdLen) > len(resp) {
			return nil, 0, fmt.Errorf("dns rdata truncated")
		}
		if rtype == 1 && rdLen == 4 {
			ip := net.IPv4(resp[off], resp[off+1], resp[off+2], resp[off+3])
			return ip, time.Duration(ttl) * time.Second, nil
		}
		off += int(rdLen)
	}
	return nil, 0, fmt.Errorf("no A record in dns response")
}

func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("dns name overflow")
		}
		b := msg[off]
		if b == 0 {
			return off + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if off+2 > len(msg) {
				return 0, fmt.Errorf("dns name pointer overflow")
			}
			return off + 2, nil
		}
		if b&0xC0 != 0 {
			return 0, fmt.Errorf("dns invalid label prefix 0x%02x", b)
		}
		off += 1 + int(b)
	}
}
