//go:build linux

package netstack

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Linux AF_UNIX datagram sockets do not report peer closure through
// getpeername or poll. The VPNFD peer is OpenConnect, so monitor its pidfd.
func monitorTunnel(ctx context.Context, tunnel net.Conn) error {
	sc, ok := tunnel.(syscall.Conn)
	if !ok {
		return fmt.Errorf("tunnel %T does not expose a raw connection", tunnel)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return fmt.Errorf("get tunnel raw connection: %w", err)
	}

	var peer *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("access tunnel socket: %w", err)
	}
	if peerErr != nil {
		return fmt.Errorf("get tunnel peer credentials: %w", peerErr)
	}

	pidfd, err := unix.PidfdOpen(int(peer.Pid), 0)
	if errors.Is(err, unix.ENOSYS) {
		log.Printf("[health] pidfd monitoring unavailable; relying on OpenConnect process supervision")
		<-ctx.Done()
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("open VPN peer pidfd for pid %d: %w", peer.Pid, err)
	}
	defer unix.Close(pidfd)

	pollfd := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := unix.Poll(pollfd, int(time.Second/time.Millisecond))
		if err != nil && err != unix.EINTR {
			return fmt.Errorf("poll VPN peer pidfd: %w", err)
		}
		if n > 0 {
			return fmt.Errorf("VPN peer process %d exited", peer.Pid)
		}
	}
}
