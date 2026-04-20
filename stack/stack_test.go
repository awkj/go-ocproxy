package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
)

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
