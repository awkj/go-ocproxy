//go:build darwin || linux

package transport

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// OpenFromEnv opens the AF_UNIX datagram inherited from OpenConnect's
// --script-tun child process on Unix.
func OpenFromEnv() (net.Conn, error) {
	value := os.Getenv("VPNFD")
	if value == "" {
		return nil, fmt.Errorf("VPNFD is required on macOS and Linux")
	}
	fd, err := strconv.Atoi(value)
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("invalid VPNFD value %q", value)
	}

	file := os.NewFile(uintptr(fd), "vpnfd")
	if file == nil {
		return nil, fmt.Errorf("open VPNFD=%d", fd)
	}
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, fmt.Errorf("convert VPNFD=%d to connection: %w", fd, err)
	}
	if closeErr != nil {
		conn.Close()
		return nil, fmt.Errorf("close inherited VPNFD=%d after duplication: %w", fd, closeErr)
	}
	return conn, nil
}
