package transport

import (
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestOpenFromEnvLinuxSocketpair(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(fds[0]), "peer")
	defer peer.Close()
	t.Setenv("VPNFD", strconv.Itoa(fds[1]))

	tunnel, err := OpenFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	if err := tunnel.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte("in")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := tunnel.Read(buf)
	if err != nil || string(buf[:n]) != "in" {
		t.Fatalf("read tunnel: %q, %v", buf[:n], err)
	}
	if _, err := tunnel.Write([]byte("out")); err != nil {
		t.Fatal(err)
	}
	n, err = peer.Read(buf)
	if err != nil || string(buf[:n]) != "out" {
		t.Fatalf("read peer: %q, %v", buf[:n], err)
	}
}
