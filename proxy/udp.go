package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const udpMaxTargets = 64
const udpIdleTimeout = 2 * time.Minute

// 地址字段与 SOCKS5 TCP 请求共用格式；域名保持原样，延迟到目标转发时解析。
func readUDPAddress(r io.Reader, atyp byte) (string, uint16, error) {
	var address []byte
	switch atyp {
	case 1:
		address = make([]byte, 4)
	case 4:
		address = make([]byte, 16)
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", 0, err
		}
		if size[0] == 0 {
			return "", 0, fmt.Errorf("empty UDP hostname")
		}
		address = make([]byte, int(size[0]))
	default:
		return "", 0, fmt.Errorf("invalid UDP address type")
	}
	if _, err := io.ReadFull(r, address); err != nil {
		return "", 0, err
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}
	host := string(address)
	if atyp != 3 {
		host = net.IP(address).String()
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

func parseUDPDatagram(packet []byte) (string, uint16, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", 0, nil, fmt.Errorf("invalid or fragmented UDP packet")
	}
	r := bytes.NewReader(packet[4:])
	host, port, err := readUDPAddress(r, packet[3])
	if err != nil || port == 0 {
		return "", 0, nil, fmt.Errorf("invalid UDP destination: %w", err)
	}
	return host, port, packet[len(packet)-r.Len():], nil
}

func appendUDPHeader(b []byte, host string, port uint16) []byte {
	b = append(b, 0, 0, 0)
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		b = append(b, 1)
		b = append(b, v4...)
	} else if ip != nil {
		b = append(b, 4)
		b = append(b, ip.To16()...)
	} else {
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, port)
}

func (s *Server) handleUDPAssociate(ctx context.Context, control net.Conn, atyp byte) {
	host, port, err := readUDPAddress(control, atyp)
	if err != nil {
		socksReply(control, socksRepAddrNotSup)
		return
	}
	peer, err := net.ResolveTCPAddr("tcp", control.RemoteAddr().String())
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsUnspecified() && !ip.Equal(peer.IP)) {
		socksReply(control, 0x02)
		return
	}
	relayUDP(ctx, control, port, s.dialUDP)
}

func (s *Server) dialUDP(ctx context.Context, host string, port uint16) (net.Conn, string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		var err error
		ip, err = s.resolve(ctx, host)
		if err != nil {
			return nil, "", err
		}
	}
	var addr tcpip.Address
	if v4 := ip.To4(); v4 != nil {
		addr = tcpip.AddrFrom4([4]byte(v4))
	} else {
		addr = tcpip.AddrFrom16([16]byte(ip.To16()))
	}
	conn, err := s.ns.DialUDP(ctx, &tcpip.FullAddress{Addr: addr, Port: port})
	return conn, ip.String(), err
}

type udpTarget struct {
	conn   net.Conn
	last   atomic.Int64
	closed atomic.Bool
}

func relayUDP(parent context.Context, control net.Conn, sourcePort uint16, dial func(context.Context, string, uint16) (net.Conn, string, error)) {
	relayUDPWithLimits(parent, control, sourcePort, dial, udpMaxTargets, udpIdleTimeout)
}

func relayUDPWithLimits(parent context.Context, control net.Conn, sourcePort uint16, dial func(context.Context, string, uint16) (net.Conn, string, error), maxTargets int, idleTimeout time.Duration) {
	local, err := net.ResolveTCPAddr("tcp", control.LocalAddr().String())
	if err != nil {
		return
	}
	peer, err := net.ResolveTCPAddr("tcp", control.RemoteAddr().String())
	if err != nil {
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP})
	if err != nil {
		socksReply(control, 0x01)
		return
	}
	defer relay.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { relay.Close(); control.Close() })
	defer stop()
	control.SetDeadline(time.Time{})
	bound := relay.LocalAddr().(*net.UDPAddr)
	reply := appendUDPHeader(nil, bound.IP.String(), uint16(bound.Port))
	reply[0] = 5
	if _, err := control.Write(reply); err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Go(func() { io.Copy(io.Discard, control); cancel() })
	targets := make(map[string]*udpTarget)
	defer func() {
		cancel()
		relay.Close()
		control.Close()
		for _, f := range targets {
			f.conn.Close()
		}
		wg.Wait()
	}()
	var source *net.UDPAddr
	buffer := make([]byte, 65535)
	for {
		// 周期性唤醒，即使客户端不再发包也能回收空闲目标。
		relay.SetReadDeadline(time.Now().Add(min(time.Second, idleTimeout)))
		n, from, readErr := relay.ReadFromUDP(buffer)
		now := time.Now()
		for key, f := range targets {
			if f.closed.Load() || now.Sub(time.Unix(0, f.last.Load())) >= idleTimeout {
				f.conn.Close()
				delete(targets, key)
			}
		}
		if readErr != nil {
			if ctx.Err() != nil {
				return
			}
			if e, ok := readErr.(net.Error); ok && e.Timeout() {
				continue
			}
			return
		}
		if !from.IP.Equal(peer.IP) || (sourcePort != 0 && from.Port != int(sourcePort)) || (source != nil && from.String() != source.String()) {
			continue
		}
		host, port, payload, err := parseUDPDatagram(buffer[:n])
		if err != nil {
			continue
		}
		if source == nil {
			source = from
			sourcePort = uint16(from.Port)
		}
		key := net.JoinHostPort(host, strconv.Itoa(int(port)))
		flow := targets[key]
		if flow == nil {
			if len(targets) >= maxTargets {
				continue
			}
			dialCtx, done := context.WithTimeout(ctx, socksDialTimeout)
			conn, ip, err := dial(dialCtx, host, port)
			done()
			if err != nil {
				continue
			}
			flow = &udpTarget{conn: conn}
			flow.last.Store(time.Now().UnixNano())
			targets[key] = flow
			stopFlow := context.AfterFunc(ctx, func() { conn.Close() })
			recipient := *source
			f := flow
			wg.Go(func() {
				defer stopFlow()
				defer f.closed.Store(true)
				defer conn.Close()
				b := make([]byte, 65535)
				header := appendUDPHeader(nil, ip, port)
				for {
					conn.SetReadDeadline(time.Now().Add(idleTimeout))
					n, err := conn.Read(b)
					if err != nil {
						if e, ok := err.(net.Error); ok && e.Timeout() && time.Since(time.Unix(0, f.last.Load())) < idleTimeout {
							continue
						}
						return
					}
					f.last.Store(time.Now().UnixNano())
					response := append(append([]byte(nil), header...), b[:n]...)
					relay.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, err := relay.WriteToUDP(response, &recipient); err != nil {
						return
					}
				}
			})
		}
		flow.last.Store(time.Now().UnixNano())
		flow.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := flow.conn.Write(payload); err != nil {
			flow.conn.Close()
			delete(targets, key)
		}
	}
}
