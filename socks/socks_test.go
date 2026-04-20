package socks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/doctor/go-ocproxy/stack"
)

// ===========================================================================
// DNS Cache (SPEC §3.2)
// ===========================================================================

func TestDNSCacheBasic(t *testing.T) {
	c := newDNSCache()

	// set + get
	c.set("example.com", net.IPv4(1, 2, 3, 4), 60*time.Second)
	ip, ok := c.get("example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if !ip.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("got %v, want 1.2.3.4", ip)
	}

	// miss
	_, ok = c.get("notfound.com")
	if ok {
		t.Fatal("expected cache miss")
	}
}

func TestDNSCacheExpiry(t *testing.T) {
	c := newDNSCache()
	// 设置一个 TTL 极短的条目（会被 clamp 到 dnsCacheMinTTL=30s）
	// 为了测试过期，直接操作 entries
	c.mu.Lock()
	c.entries["expired.com"] = dnsCacheEntry{
		ip:     net.IPv4(1, 1, 1, 1),
		expiry: time.Now().Add(-1 * time.Second),
	}
	c.mu.Unlock()

	_, ok := c.get("expired.com")
	if ok {
		t.Fatal("expected expired entry to be a miss")
	}
}

func TestDNSCacheTTLClamp(t *testing.T) {
	c := newDNSCache()

	// TTL 太短 → clamp 到 30s
	c.set("short.com", net.IPv4(1, 1, 1, 1), 1*time.Second)
	c.mu.RLock()
	e := c.entries["short.com"]
	c.mu.RUnlock()
	remaining := time.Until(e.expiry)
	if remaining < 29*time.Second {
		t.Errorf("TTL should be clamped to ≥30s, got %v remaining", remaining)
	}

	// TTL 太长 → clamp 到 1h
	c.set("long.com", net.IPv4(2, 2, 2, 2), 2*time.Hour)
	c.mu.RLock()
	e = c.entries["long.com"]
	c.mu.RUnlock()
	remaining = time.Until(e.expiry)
	if remaining > 61*time.Minute {
		t.Errorf("TTL should be clamped to ≤1h, got %v remaining", remaining)
	}
}

func TestDNSCacheMaxSize(t *testing.T) {
	c := newDNSCache()

	// 填满到上限
	for i := range dnsCacheMaxSize {
		c.set(net.IPv4(byte(i>>8), byte(i), 0, 0).String(), net.IPv4(byte(i>>8), byte(i), 0, 0), time.Minute)
	}
	if c.size() != dnsCacheMaxSize {
		t.Fatalf("expected size %d, got %d", dnsCacheMaxSize, c.size())
	}

	// 再加一个 → 应淘汰最老的，总数不超限
	c.set("overflow.com", net.IPv4(9, 9, 9, 9), time.Minute)
	if c.size() > dnsCacheMaxSize {
		t.Fatalf("cache exceeded max size: %d > %d", c.size(), dnsCacheMaxSize)
	}

	// 新条目可查到
	ip, ok := c.get("overflow.com")
	if !ok || !ip.Equal(net.IPv4(9, 9, 9, 9)) {
		t.Fatal("newly added entry should be retrievable")
	}
}

func TestDNSCacheEvictExpired(t *testing.T) {
	c := newDNSCache()
	c.mu.Lock()
	c.entries["alive"] = dnsCacheEntry{ip: net.IPv4(1, 1, 1, 1), expiry: time.Now().Add(time.Hour)}
	c.entries["dead1"] = dnsCacheEntry{ip: net.IPv4(2, 2, 2, 2), expiry: time.Now().Add(-time.Second)}
	c.entries["dead2"] = dnsCacheEntry{ip: net.IPv4(3, 3, 3, 3), expiry: time.Now().Add(-time.Minute)}
	c.mu.Unlock()

	c.evictExpired()

	if c.size() != 1 {
		t.Fatalf("expected 1 entry after eviction, got %d", c.size())
	}
	if _, ok := c.get("alive"); !ok {
		t.Fatal("alive entry should survive eviction")
	}
}

// ===========================================================================
// DNS 报文构造与解析 (SPEC §6.1)
// ===========================================================================

func TestBuildDNSQuery(t *testing.T) {
	q, err := buildDNSQuery("www.example.com", 0x1234)
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}

	// ID
	if binary.BigEndian.Uint16(q[0:2]) != 0x1234 {
		t.Error("wrong ID")
	}
	// Flags: standard query, RD=1
	if binary.BigEndian.Uint16(q[2:4]) != 0x0100 {
		t.Error("wrong flags")
	}
	// QDCOUNT = 1
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Error("wrong QDCOUNT")
	}
	// 包含 "www", "example", "com" 三个 label
	off := 12
	labels := []string{"www", "example", "com"}
	for _, label := range labels {
		l := int(q[off])
		off++
		got := string(q[off : off+l])
		off += l
		if got != label {
			t.Errorf("expected label %q, got %q", label, got)
		}
	}
	if q[off] != 0 {
		t.Error("missing root label")
	}
}

func TestBuildDNSQueryInvalidLabel(t *testing.T) {
	_, err := buildDNSQuery("", 1)
	if err == nil {
		t.Error("expected error for empty name")
	}
}

func TestParseDNSResponse(t *testing.T) {
	// 构造一个最小的 DNS A 记录响应
	resp := make([]byte, 0, 64)
	resp = binary.BigEndian.AppendUint16(resp, 0xABCD)    // ID
	resp = binary.BigEndian.AppendUint16(resp, 0x8180)    // Flags: response, no error
	resp = binary.BigEndian.AppendUint16(resp, 1)         // QDCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 1)         // ANCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0)         // NSCOUNT
	resp = binary.BigEndian.AppendUint16(resp, 0)         // ARCOUNT
	// Question: www.example.com A IN
	resp = append(resp, 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	resp = binary.BigEndian.AppendUint16(resp, 1) // QTYPE=A
	resp = binary.BigEndian.AppendUint16(resp, 1) // QCLASS=IN
	// Answer: compressed name pointer to offset 12
	resp = append(resp, 0xC0, 0x0C)               // name pointer
	resp = binary.BigEndian.AppendUint16(resp, 1)  // TYPE=A
	resp = binary.BigEndian.AppendUint16(resp, 1)  // CLASS=IN
	resp = binary.BigEndian.AppendUint32(resp, 300) // TTL=300s
	resp = binary.BigEndian.AppendUint16(resp, 4)  // RDLENGTH=4
	resp = append(resp, 93, 184, 216, 34)          // 93.184.216.34

	ip, ttl, err := parseDNSResponse(resp, 0xABCD)
	if err != nil {
		t.Fatalf("parseDNSResponse: %v", err)
	}
	if !ip.Equal(net.IPv4(93, 184, 216, 34)) {
		t.Errorf("got IP %v, want 93.184.216.34", ip)
	}
	if ttl != 300*time.Second {
		t.Errorf("got TTL %v, want 300s", ttl)
	}
}

func TestParseDNSResponseIDMismatch(t *testing.T) {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], 0x0001)
	_, _, err := parseDNSResponse(resp, 0x0002)
	if err == nil {
		t.Fatal("expected error for ID mismatch")
	}
}

func TestParseDNSResponseRcode(t *testing.T) {
	resp := make([]byte, 12)
	binary.BigEndian.PutUint16(resp[0:2], 0x0001)
	binary.BigEndian.PutUint16(resp[2:4], 0x8183) // rcode=3 (NXDOMAIN)
	_, _, err := parseDNSResponse(resp, 0x0001)
	if err == nil {
		t.Fatal("expected error for rcode 3")
	}
}

func TestSkipDNSName(t *testing.T) {
	// "www.example.com" encoded
	msg := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	off, err := skipDNSName(msg, 0)
	if err != nil {
		t.Fatalf("skipDNSName: %v", err)
	}
	if off != len(msg) {
		t.Errorf("offset = %d, want %d", off, len(msg))
	}
}

func TestSkipDNSNameCompression(t *testing.T) {
	msg := []byte{0xC0, 0x0C} // compression pointer
	off, err := skipDNSName(msg, 0)
	if err != nil {
		t.Fatalf("skipDNSName: %v", err)
	}
	if off != 2 {
		t.Errorf("offset = %d, want 2", off)
	}
}

// ===========================================================================
// Stats (SPEC §2.6)
// ===========================================================================

func TestStats(t *testing.T) {
	var s Stats

	s.connOpened()
	s.connOpened()
	s.connOpened()

	if s.ActiveConns.Load() != 3 {
		t.Errorf("active = %d, want 3", s.ActiveConns.Load())
	}
	if s.TotalConns.Load() != 3 {
		t.Errorf("total = %d, want 3", s.TotalConns.Load())
	}
	if s.MaxConns.Load() != 3 {
		t.Errorf("max = %d, want 3", s.MaxConns.Load())
	}

	s.connClosed()
	if s.ActiveConns.Load() != 2 {
		t.Errorf("active = %d, want 2", s.ActiveConns.Load())
	}
	// max 不应该降
	if s.MaxConns.Load() != 3 {
		t.Errorf("max should stay 3, got %d", s.MaxConns.Load())
	}
}

// ===========================================================================
// SOCKS5 协议测试 (SPEC §2.1)
// ===========================================================================

func setupTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	ns, err := stack.NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	s := NewServer(ns, "127.0.0.1:0", nil, "")
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.Serve(ctx)
	t.Cleanup(func() {
		cancel()
		s.Close(time.Second)
	})
	return s, s.listener.Addr().String()
}

func dialTest(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

// SK-PROTO-1: 非 SOCKS5 版本应回复 {0x05, 0xFF}
func TestSOCKS5BadVersion(t *testing.T) {
	_, addr := setupTestServer(t)
	conn := dialTest(t, addr)
	defer conn.Close()

	// ���送 SOCKS4 版本号
	conn.Write([]byte{0x04, 0x01, 0x00})

	buf := make([]byte, 2)
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 2 || buf[0] != 0x05 || buf[1] != 0xFF {
		t.Errorf("expected {0x05, 0xFF}, got %x", buf[:n])
	}
}

// SK-PROTO-2: 不支持的命令应回复 REP=0x07
func TestSOCKS5UnsupportedCommand(t *testing.T) {
	_, addr := setupTestServer(t)
	conn := dialTest(t, addr)
	defer conn.Close()

	// 正常 auth 握手
	conn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		t.Fatalf("auth failed: %x", authResp)
	}

	// 发 UDP_ASSOCIATE (0x03) 命令
	conn.Write([]byte{
		0x05, 0x03, 0x00, 0x01,
		127, 0, 0, 1,
		0x00, 0x50,
	})

	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	if resp[1] != socksRepCmdNotSupp {
		t.Errorf("expected REP=0x%02x, got 0x%02x", socksRepCmdNotSupp, resp[1])
	}
}

// SK-PROTO-3: IPv6 地址类型应回复 REP=0x08
func TestSOCKS5IPv6Address(t *testing.T) {
	_, addr := setupTestServer(t)
	conn := dialTest(t, addr)
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)

	// CONNECT + ATYP=0x04 (IPv6) + 16字节地址 + 2字节端口
	req := []byte{0x05, 0x01, 0x00, 0x04}
	req = append(req, make([]byte, 16)...) // ::0
	req = append(req, 0x00, 0x50)
	conn.Write(req)

	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	if resp[1] != socksRepAddrNotSup {
		t.Errorf("expected REP=0x%02x, got 0x%02x", socksRepAddrNotSup, resp[1])
	}
}

// SK-PROTO-4: 未知地址类型回复 REP=0x08
func TestSOCKS5UnknownAddressType(t *testing.T) {
	_, addr := setupTestServer(t)
	conn := dialTest(t, addr)
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)

	// CONNECT + 未知 ATYP=0x99
	conn.Write([]byte{0x05, 0x01, 0x00, 0x99})

	resp := make([]byte, 10)
	n, _ := io.ReadAtLeast(conn, resp, 2)
	if n >= 2 && resp[1] != socksRepAddrNotSup {
		t.Errorf("expected REP=0x%02x, got 0x%02x", socksRepAddrNotSup, resp[1])
	}
}

// SK-IP-1: resolve 不返回 IPv6 导致 panic
func TestSOCKS5IPv4OnlyResolve(t *testing.T) {
	_, addr := setupTestServer(t)
	conn := dialTest(t, addr)
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)

	// CONNECT to "localhost" via domain — 不应 panic
	domain := "localhost"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, domain...)
	req = append(req, 0x00, 0x50)
	conn.Write(req)

	// 读响应（可能成功也可能失败，关键是不 panic）
	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	t.Logf("reply for localhost: REP=0x%02x (no panic = pass)", resp[1])
}

// SK-LIFE-1: 等两个方向都结束
func TestSOCKS5BidirectionalCopy(t *testing.T) {
	s, addr := setupTestServer(t)

	conn := dialTest(t, addr)
	defer conn.Close()

	conn.Write([]byte{0x05, 0x01, 0x00})
	authResp := make([]byte, 2)
	io.ReadFull(conn, authResp)

	// CONNECT to 10.0.0.1:1 (will fail — gVisor 内部没有监听)
	conn.Write([]byte{
		0x05, 0x01, 0x00, 0x01,
		10, 0, 0, 1,
		0x00, 0x01,
	})

	resp := make([]byte, 10)
	io.ReadFull(conn, resp)
	// 连接可能失败（REP != 0x00），但不应 panic
	t.Logf("connect reply: REP=0x%02x", resp[1])

	// 验证统计计数器递增
	if s.Stats.TotalConns.Load() < 1 {
		t.Error("TotalConns should be ≥ 1")
	}
}

// SK-LIMIT-1: 连接数达上限时拒绝新连接
func TestSOCKS5ConnectionLimit(t *testing.T) {
	s, addr := setupTestServer(t)

	// 手动填满连接信号量，留 0 个空位
	for range maxConnections {
		s.connLimit <- struct{}{}
	}

	// 新连接应该被拒绝（服务端直接 Close）
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed by server")
	}
	// 应该是 EOF（服务端关了连接）
	t.Logf("rejected connection got: %v (expected EOF or reset)", err)

	// SK-LIMIT-2: 释放一个槽位后新连接应该能接入
	<-s.connLimit
	conn2 := dialTest(t, addr)
	defer conn2.Close()
	conn2.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	n, err := io.ReadFull(conn2, resp)
	if err != nil || n != 2 {
		t.Fatalf("second connection failed: %v", err)
	}
	if resp[0] != 0x05 {
		t.Errorf("expected SOCKS5 response, got 0x%02x", resp[0])
	}

	// 清空信号量
	for range maxConnections - 1 {
		<-s.connLimit
	}
}

// ===========================================================================
// DNS 域名后缀 (SPEC §3.1)
// ===========================================================================

func TestResolveCacheHit(t *testing.T) {
	ns, err := stack.NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	s := NewServer(ns, "127.0.0.1:0", nil, "")
	// 预填 cache
	s.cache.set("cached.example.com", net.IPv4(1, 2, 3, 4), time.Minute)

	ip, err := s.resolve(context.Background(), "cached.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !ip.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Errorf("got %v, want 1.2.3.4", ip)
	}
	if s.Stats.DNSCacheHit.Load() != 1 {
		t.Errorf("cache hit = %d, want 1", s.Stats.DNSCacheHit.Load())
	}
}

func TestResolveCacheMiss(t *testing.T) {
	ns, err := stack.NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	s := NewServer(ns, "127.0.0.1:0", nil, "")

	// resolve a name not in cache — regardless of DNS result, miss counter should increment
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = s.resolve(ctx, "localhost")
	if s.Stats.DNSCacheMiss.Load() != 1 {
		t.Errorf("cache miss = %d, want 1", s.Stats.DNSCacheMiss.Load())
	}
}

// ===========================================================================
// DumpStats 不 panic
// ===========================================================================

func TestDumpStats(t *testing.T) {
	ns, err := stack.NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	s := NewServer(ns, "127.0.0.1:0", nil, "")
	s.Stats.connOpened()
	s.Stats.DNSCacheHit.Add(10)
	s.DumpStats() // 不 panic 就 pass
}
