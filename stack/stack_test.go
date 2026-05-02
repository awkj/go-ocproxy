package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// scriptedConn 是按脚本返回 Write 错误的 net.Conn mock，用于精确测试
// writeOutboundWithRetry 在各种错误序列下的行为。脚本耗尽后默认成功。
type scriptedConn struct {
	net.Conn // embed nil：未脚本化的方法被调用直接 panic，定位测试漏洞

	mu      sync.Mutex
	results []error // 第 i 次 Write 返回 results[i]；nil 表示成功
	calls   int
}

func (c *scriptedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	idx := c.calls
	c.calls++
	if idx >= len(c.results) {
		return len(b), nil
	}
	if err := c.results[idx]; err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *scriptedConn) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// withFastRetry 把退避参数缩到测试友好的范围（10 次合计 < 1ms），返回还原函数。
func withFastRetry(t *testing.T) func() {
	t.Helper()
	origMax := outboundMaxRetries
	origInit := outboundInitialDelay
	origMaxDelay := outboundMaxDelay
	outboundInitialDelay = 0
	outboundMaxDelay = 0
	return func() {
		outboundMaxRetries = origMax
		outboundInitialDelay = origInit
		outboundMaxDelay = origMaxDelay
	}
}

func TestIsFatalWriteErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"EPIPE", syscall.EPIPE, true},
		{"EBADF", syscall.EBADF, true},
		{"ECONNRESET", syscall.ECONNRESET, true},
		{"ENOTCONN", syscall.ENOTCONN, true},
		{"ErrClosedPipe", io.ErrClosedPipe, true},
		{"ErrClosed", os.ErrClosed, true},
		{"ENOBUFS", syscall.ENOBUFS, false},
		{"EMSGSIZE", syscall.EMSGSIZE, false},
		{"wrapped_EPIPE", fmt.Errorf("wrap: %w", syscall.EPIPE), true},
		{"wrapped_ENOBUFS", fmt.Errorf("wrap: %w", syscall.ENOBUFS), false},
		{"random_error", errors.New("something went wrong"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFatalWriteErr(tc.err); got != tc.want {
				t.Errorf("isFatalWriteErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNewNetStack(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		ns, err := NewNetStack("10.0.0.1", 1500)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ns.Stack == nil || ns.Link == nil {
			t.Fatal("Stack or Link is nil")
		}
	})
	t.Run("invalid_IP", func(t *testing.T) {
		_, err := NewNetStack("not-an-ip", 1500)
		if err == nil {
			t.Fatal("expected error for invalid IP")
		}
	})
	t.Run("empty_IP", func(t *testing.T) {
		_, err := NewNetStack("", 1500)
		if err == nil {
			t.Fatal("expected error for empty IP")
		}
	})
}

func socketpair(t *testing.T) (vpnSide *os.File, appSide *os.File) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return os.NewFile(uintptr(fds[0]), "vpn"), os.NewFile(uintptr(fds[1]), "app")
}

func makeIPv4Packet(totalLen int, src, dst [4]byte) []byte {
	if totalLen < 20 {
		totalLen = 20
	}
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	return pkt
}

// S-IN-1/2/4: one-shot datagram read, short packet discard
func TestRunInboundDatagram(t *testing.T) {
	ns, err := NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	vpn, app := socketpair(t)
	defer vpn.Close()
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- ns.Run(ctx, app, app) }()

	pkt := makeIPv4Packet(40, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	vpn.Write(pkt)

	// short packet (<20 bytes) silently discarded (S-IN-2)
	vpn.Write([]byte{0x45, 0x00})

	// another normal packet still works
	vpn.Write(makeIPv4Packet(40, [4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 1}))

	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-errCh:
		t.Fatalf("Run exited unexpectedly: %v", err)
	default:
	}
	cancel()
	// 等 Run 真正退出再让测试 return；否则 defer app.Close() 可能跟 Run 内部
	// 还没跑完的 net.FileConn(input) 拿 fd 的操作发生 race。
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit within 2s after cancel")
	}
}

// S-HEALTH-2: health check detects dead VPN via write probe
func TestRunHealthCheckDetectsDeadVPN(t *testing.T) {
	ns, err := NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	vpn, app := socketpair(t)
	defer app.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- ns.Run(context.Background(), app, app) }()

	time.Sleep(200 * time.Millisecond)

	// close VPN peer; health check write probe gets EPIPE/ENOTCONN
	vpn.Close()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error")
		}
		t.Logf("VPN death detected: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not detect VPN death within 5s")
	}
}

// S-OUT-1: outbound fatal error propagates to main loop
func TestRunOutboundFatalNotifiesMainLoop(t *testing.T) {
	ns, err := NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}

	// separate socketpairs: input stays alive, output peer gets closed
	vpnIn, appIn := socketpair(t)
	vpnOut, appOut := socketpair(t)
	defer vpnIn.Close()
	defer appIn.Close()
	defer appOut.Close()

	errCh := make(chan error, 1)
	go func() { errCh <- ns.Run(context.Background(), appIn, appOut) }()

	// inject traffic so gVisor produces outbound packets
	pkt := makeIPv4Packet(40, [4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1})
	vpnIn.Write(pkt)
	time.Sleep(100 * time.Millisecond)

	// close output peer → outbound writes fail with EPIPE
	vpnOut.Close()

	// keep injecting so gVisor keeps producing outbound traffic
	go func() {
		for range 50 {
			vpnIn.Write(pkt)
			time.Sleep(20 * time.Millisecond)
		}
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error")
		}
		t.Logf("Run returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s")
	}
}

// W-RETRY-1: 第一次 Write 成功，不重试
func TestWriteOutboundWithRetry_Success(t *testing.T) {
	defer withFastRetry(t)()
	conn := &scriptedConn{results: []error{nil}}
	if err := writeOutboundWithRetry(context.Background(), conn, []byte("x")); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if c := conn.Calls(); c != 1 {
		t.Errorf("expected 1 Write, got %d", c)
	}
}

// W-RETRY-2: ENOBUFS 几次后成功，最终返回 nil
func TestWriteOutboundWithRetry_TransientThenSuccess(t *testing.T) {
	defer withFastRetry(t)()
	conn := &scriptedConn{results: []error{
		syscall.ENOBUFS,
		syscall.ENOBUFS,
		syscall.ENOBUFS,
		nil,
	}}
	if err := writeOutboundWithRetry(context.Background(), conn, []byte("x")); err != nil {
		t.Fatalf("expected nil after retries, got %v", err)
	}
	if c := conn.Calls(); c != 4 {
		t.Errorf("expected 4 Write calls, got %d", c)
	}
}

// W-RETRY-3: ENOBUFS 持续返回耗尽重试上限，错误回传给调用方（由调用方决定丢包）
func TestWriteOutboundWithRetry_TransientExhausted(t *testing.T) {
	defer withFastRetry(t)()
	outboundMaxRetries = 5 // 测试覆盖
	conn := &scriptedConn{results: []error{
		syscall.ENOBUFS, syscall.ENOBUFS, syscall.ENOBUFS,
		syscall.ENOBUFS, syscall.ENOBUFS,
	}}
	err := writeOutboundWithRetry(context.Background(), conn, []byte("x"))
	if !errors.Is(err, syscall.ENOBUFS) {
		t.Fatalf("expected ENOBUFS after exhaust, got %v", err)
	}
	if c := conn.Calls(); c != 5 {
		t.Errorf("expected 5 Write calls (= maxRetries), got %d", c)
	}
}

// W-RETRY-4: fatal 错误立即返回，不重试（避免 ENOBUFS-style 退避后才发现连接死了）
func TestWriteOutboundWithRetry_FatalImmediate(t *testing.T) {
	defer withFastRetry(t)()
	cases := []error{
		syscall.EPIPE, syscall.EBADF, syscall.ECONNRESET,
		syscall.ENOTCONN, io.ErrClosedPipe, os.ErrClosed,
	}
	for _, fatal := range cases {
		t.Run(fatal.Error(), func(t *testing.T) {
			conn := &scriptedConn{results: []error{fatal, nil}}
			err := writeOutboundWithRetry(context.Background(), conn, []byte("x"))
			if !errors.Is(err, fatal) {
				t.Fatalf("expected %v, got %v", fatal, err)
			}
			if c := conn.Calls(); c != 1 {
				t.Errorf("expected 1 Write call (no retry), got %d", c)
			}
		})
	}
}

// W-RETRY-5: ctx 在退避中被取消，立即返回 ctx.Err()
func TestWriteOutboundWithRetry_ContextCancel(t *testing.T) {
	// 这个测试需要真实退避才能让 ctx 在 sleep 时被取消，所以不用 withFastRetry
	origInit := outboundInitialDelay
	outboundInitialDelay = 50 * time.Millisecond
	defer func() { outboundInitialDelay = origInit }()

	ctx, cancel := context.WithCancel(context.Background())
	conn := &scriptedConn{results: []error{
		syscall.ENOBUFS, syscall.ENOBUFS, syscall.ENOBUFS,
	}}

	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := writeOutboundWithRetry(ctx, conn, []byte("x"))
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// 应该在 ~10ms 退出，远短于 maxRetries × 50ms = 500ms。给宽容一点
	if elapsed > 200*time.Millisecond {
		t.Errorf("expected fast cancel (<200ms), took %v", elapsed)
	}
}

// W-RETRY-6: ErrDeadlineExceeded 立即返回（ctx cancel 通过 SetDeadline 传导，不应被
// 当成 transient 重试，否则下游 Run 收不到退出信号）
func TestWriteOutboundWithRetry_DeadlineExceededImmediate(t *testing.T) {
	defer withFastRetry(t)()
	conn := &scriptedConn{results: []error{os.ErrDeadlineExceeded, nil}}
	err := writeOutboundWithRetry(context.Background(), conn, []byte("x"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected ErrDeadlineExceeded, got %v", err)
	}
	if c := conn.Calls(); c != 1 {
		t.Errorf("expected 1 Write call, got %d", c)
	}
}

// W-RETRY-7: maxRetries=0 退化为不写（防御性边界）
func TestWriteOutboundWithRetry_ZeroRetries(t *testing.T) {
	defer withFastRetry(t)()
	outboundMaxRetries = 0
	conn := &scriptedConn{}
	err := writeOutboundWithRetry(context.Background(), conn, []byte("x"))
	if err != nil {
		t.Fatalf("expected nil (no attempts made), got %v", err)
	}
	if c := conn.Calls(); c != 0 {
		t.Errorf("expected 0 Write calls, got %d", c)
	}
}

// context cancel makes Run return immediately
func TestRunContextCancel(t *testing.T) {
	ns, err := NewNetStack("10.0.0.1", 1500)
	if err != nil {
		t.Fatalf("NewNetStack: %v", err)
	}
	vpn, app := socketpair(t)
	defer vpn.Close()
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- ns.Run(ctx, app, app) }()

	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		t.Logf("Run returned after cancel: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}
