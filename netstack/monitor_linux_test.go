package netstack

import (
	"context"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestMonitorTunnelLinuxWaitsForContext(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	tunnelFile := os.NewFile(uintptr(fds[0]), "tunnel")
	peer := os.NewFile(uintptr(fds[1]), "peer")
	defer peer.Close()
	tunnel, err := net.FileConn(tunnelFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnelFile.Close(); err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- monitorTunnel(ctx, tunnel) }()

	select {
	case err := <-errCh:
		t.Fatalf("monitorTunnel exited before cancellation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Fatalf("monitorTunnel error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("monitorTunnel did not stop after cancellation")
	}
}
