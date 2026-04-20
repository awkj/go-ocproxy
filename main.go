package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/doctor/go-ocproxy/socks"
	"github.com/doctor/go-ocproxy/stack"
)

const Version = "1.1.0 (Go-gVisor rewrite)"

func main() {
	socksPort := flag.String("D", "1080", "SOCKS5 dynamic port forward")
	showVersion := flag.Bool("V", false, "Show version")
	localIP := flag.String("ip", "", "Internal IPv4 address")
	mtu := flag.Int("mtu", 1500, "MTU")
	dnsDomain := flag.String("o", "", "Default DNS domain suffix (CISCO_DEF_DOMAIN)")
	keepalive := flag.Int("k", 0, "TCP keepalive interval in seconds (0=disabled)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("go-ocproxy version: %s\n", Version)
		return
	}

	if *localIP == "" {
		*localIP = os.Getenv("INTERNAL_IP4_ADDRESS")
	}
	if *localIP == "" {
		log.Fatal("[main] Internal IP address not set. Use -ip or run via openconnect.")
	}

	if envMTU := os.Getenv("INTERNAL_IP4_MTU"); envMTU != "" {
		if m, err := strconv.Atoi(envMTU); err == nil {
			*mtu = m
		}
	}

	var dnsServers []string
	if envDNS := os.Getenv("INTERNAL_IP4_DNS"); envDNS != "" {
		dnsServers = strings.Fields(envDNS)
	}

	if *dnsDomain == "" {
		*dnsDomain = os.Getenv("CISCO_DEF_DOMAIN")
	}

	listenAddr := "127.0.0.1:" + *socksPort

	log.Printf("[main] -----------------------------------------")
	log.Printf("[main]   go-ocproxy %s", Version)
	log.Printf("[main] -----------------------------------------")
	log.Printf("[main] Listening:     %s (SOCKS5)", listenAddr)
	log.Printf("[main] Internal IP:   %s", *localIP)
	log.Printf("[main] MTU:           %d", *mtu)
	log.Printf("[main] DNS Servers:   %v", dnsServers)
	if *dnsDomain != "" {
		log.Printf("[main] DNS Domain:    %s", *dnsDomain)
	}
	if *keepalive > 0 {
		log.Printf("[main] TCP Keepalive: %ds", *keepalive)
	}

	ns, err := stack.NewNetStack(*localIP, uint32(*mtu))
	if err != nil {
		log.Fatalf("[main] Failed to initialize netstack: %v", err)
	}
	if *keepalive > 0 {
		ns.TCPKeepalive = time.Duration(*keepalive) * time.Second
	}

	server := socks.NewServer(ns, listenAddr, dnsServers, *dnsDomain)
	if err := server.Listen(); err != nil {
		log.Fatalf("[main] SOCKS5 listen failed: %v", err)
	}

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	go func() {
		if err := server.Serve(ctx); err != nil {
			log.Printf("[socks] serve error: %v", err)
		}
	}()

	var vpnFile *os.File
	if vpnfdStr := os.Getenv("VPNFD"); vpnfdStr != "" {
		fd, err := strconv.Atoi(vpnfdStr)
		if err != nil {
			log.Fatalf("[main] Invalid VPNFD value %q: %v", vpnfdStr, err)
		}
		vpnFile = os.NewFile(uintptr(fd), "vpnfd")
		if vpnFile == nil {
			log.Fatalf("[main] Failed to open VPNFD=%d", fd)
		}
		defer vpnFile.Close()
		log.Printf("[main] Using VPNFD=%d for tunnel I/O", fd)
	} else {
		log.Printf("[main] VPNFD not set, falling back to stdin/stdout")
	}

	var input, output *os.File
	if vpnFile != nil {
		input = vpnFile
		output = vpnFile
	} else {
		input = os.Stdin
		output = os.Stdout
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	statsCh := make(chan os.Signal, 1)
	signal.Notify(statsCh, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case sig := <-shutdownCh:
				log.Printf("[main] received %v, shutting down gracefully...", sig)
				ctxCancel()
				server.Close(5 * time.Second)
				return
			case <-statsCh:
				server.DumpStats()
			}
		}
	}()

	if err := ns.Run(ctx, input, output); err != nil {
		if !isCleanShutdownErr(err) {
			log.Printf("[main] netstack error: %v", err)
		}
	}
	log.Printf("[main] shutdown complete")
}

func isCleanShutdownErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EBADF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "file already closed") ||
		strings.Contains(msg, "use of closed") ||
		strings.Contains(msg, "bad file descriptor")
}
