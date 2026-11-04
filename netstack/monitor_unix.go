//go:build darwin

package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// monitorTunnel detects a closed OpenConnect AF_UNIX datagram peer. A zero-byte
// write is not a safe probe for datagram sockets, so inspect the connected peer
// without injecting data into the tunnel.
func monitorTunnel(ctx context.Context, tunnel net.Conn) error {
	sc, ok := tunnel.(syscall.Conn)
	if !ok {
		return fmt.Errorf("tunnel %T does not expose a raw connection", tunnel)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("get tunnel raw connection: %w", err)
	}

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var peerErr error
			if err := raw.Control(func(fd uintptr) {
				_, peerErr = unix.Getpeername(int(fd))
			}); err != nil {
				return fmt.Errorf("access tunnel socket: %w", err)
			}
			if peerErr == nil {
				continue
			}
			if errors.Is(peerErr, unix.ENOTCONN) || errors.Is(peerErr, unix.ECONNRESET) ||
				errors.Is(peerErr, unix.ECONNREFUSED) || errors.Is(peerErr, unix.EBADF) {
				return peerErr
			}
		}
	}
}
