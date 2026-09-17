package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
)

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
	return s.dnsLookups.do(ctx, name, func(queryCtx context.Context) (net.IP, error) {
		return s.resolveUncached(queryCtx, name)
	})
}

func (s *Server) resolveUncached(ctx context.Context, name string) (net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Another flight may have completed between the first cache read and joining.
	if ip, found, negative := s.cache.get(name); found {
		if negative {
			return nil, fmt.Errorf("negative cache hit for %s", name)
		}
		return ip, nil
	}

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

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		// 写入负缓存：5s 内同一域名再来也直接失败，不打 DNS
		if cacheableDNSFailure(err) {
			s.cache.setNegative(name)
		}
		return nil, err
	}
	s.cache.set(name, ip, ttl)
	return ip, nil
}

func cacheableDNSFailure(err error) bool {
	var networkError net.Error
	return err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
		!(errors.As(err, &networkError) && networkError.Timeout())
}

func (s *Server) queryDNS(ctx context.Context, name string) (net.IP, time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if len(s.dnsServers) == 0 {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
		if err != nil {
			return nil, 0, err
		}
		for _, addr := range addrs {
			if addr.Is4() {
				v4 := addr.As4()
				return net.IP(v4[:]), dnsCacheFallbackTTL, nil
			}
		}
		if s.ns.HasIPv6 {
			for _, addr := range addrs {
				if addr.Is6() {
					v6 := addr.As16()
					return net.IP(v6[:]), dnsCacheFallbackTTL, nil
				}
			}
		}
		return nil, 0, fmt.Errorf("no usable IP address for %s", name)
	}

	start := rand.IntN(len(s.dnsServers))
	var lastErr error
	for i := range dnsMaxAttempts {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		server := s.dnsServers[(start+i)%len(s.dnsServers)]
		ip, ttl, err := s.dnsQueryType(ctx, name, server, dnsmessage.TypeA)
		if err == nil && ip != nil {
			return ip, ttl, nil
		}
		if errors.Is(err, errDNSRcode) {
			break
		}
		if err == nil {
			err = fmt.Errorf("dns query for %q returned no result", name)
		}
		lastErr = err
	}

	if s.ns.HasIPv6 {
		start = rand.IntN(len(s.dnsServers))
		for i := range dnsMaxAttempts {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			server := s.dnsServers[(start+i)%len(s.dnsServers)]
			ip, ttl, err := s.dnsQueryType(ctx, name, server, dnsmessage.TypeAAAA)
			if err == nil && ip != nil {
				return ip, ttl, nil
			}
			if errors.Is(err, errDNSRcode) {
				break
			}
			if err == nil {
				err = fmt.Errorf("dns AAAA query for %q returned no result", name)
			}
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no usable IP address for %s", name)
	}
	return nil, 0, lastErr
}

// ---------------------------------------------------------------------------
// DNS 协议实现
// ---------------------------------------------------------------------------

func (s *Server) dnsQueryType(ctx context.Context, name, server string, qtype dnsmessage.Type) (net.IP, time.Duration, error) {
	dnsAddr := server
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}
	host, portStr, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		// IPv6 字面量不带方括号时 SplitHostPort 会失败，尝试加端口重试
		if ip := net.ParseIP(server); ip != nil {
			host = server
			portStr = "53"
		} else {
			return nil, 0, fmt.Errorf("invalid dns server %q: %w", server, err)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid dns server port %q: %w", portStr, err)
	}
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return nil, 0, &net.AddrError{Err: "invalid dns server", Addr: host}
	}
	var addr *tcpip.FullAddress
	if v4 := parsedIP.To4(); v4 != nil {
		addr = &tcpip.FullAddress{
			Addr: tcpip.AddrFrom4([4]byte(v4)),
			Port: uint16(port),
		}
	} else {
		addr = &tcpip.FullAddress{
			Addr: tcpip.AddrFrom16([16]byte(parsedIP.To16())),
			Port: uint16(port),
		}
	}

	id := uint16(rand.Uint32())
	query, err := buildDNSQuery(name, id, qtype)
	if err != nil {
		return nil, 0, err
	}

	resp, truncated, udpErr := s.queryUDP(ctx, addr, query)
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if udpErr == nil && !truncated {
		return parseDNSResponse(resp, id)
	}
	resp, tcpErr := s.queryTCP(ctx, addr, query)
	if tcpErr != nil {
		if udpErr != nil {
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
	deadline, _ := dialCtx.Deadline()
	conn.SetDeadline(deadline)
	stopCancel := context.AfterFunc(dialCtx, func() { conn.SetDeadline(time.Now()) })
	defer stopCancel()

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
	deadline, _ := dialCtx.Deadline()
	conn.SetDeadline(deadline)
	stopCancel := context.AfterFunc(dialCtx, func() { conn.SetDeadline(time.Now()) })
	defer stopCancel()

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

func buildDNSQuery(name string, id uint16, qtype dnsmessage.Type) ([]byte, error) {
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
		Type:  qtype,
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
		switch ah.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return nil, 0, fmt.Errorf("parse A: %w", err)
			}
			ip := net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3])
			return ip, time.Duration(ah.TTL) * time.Second, nil
		case dnsmessage.TypeAAAA:
			aaaa, err := p.AAAAResource()
			if err != nil {
				return nil, 0, fmt.Errorf("parse AAAA: %w", err)
			}
			ip := net.IP(aaaa.AAAA[:])
			return ip, time.Duration(ah.TTL) * time.Second, nil
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, 0, fmt.Errorf("skip answer: %w", err)
			}
		}
	}
	return nil, 0, fmt.Errorf("no A/AAAA record in dns response")
}
