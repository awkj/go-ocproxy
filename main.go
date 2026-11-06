package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/awkj/go-ocproxy/internal/sigctx"
	"github.com/awkj/go-ocproxy/netstack"
	"github.com/awkj/go-ocproxy/proxy"
	"github.com/awkj/go-ocproxy/transport"
)

// version is optionally injected from a release tag or source commit through
// -ldflags. Local builds fall back to Go's embedded VCS metadata.
var version string

func main() {
	if err := run(); err != nil {
		log.Printf("[main] fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	socksPort := flag.String("D", "1080", "Listen port for SOCKS5/HTTP proxy (auto-sniffed)")
	showVersion := flag.Bool("V", false, "Show version")
	localIP := flag.String("ip", "", "Internal IPv4 address")
	localIP6 := flag.String("ip6", "", "Internal IPv6 address")
	mtu := flag.Int("mtu", 1500, "MTU")
	dnsDomain := flag.String("o", "", "Default DNS domain suffix (CISCO_DEF_DOMAIN)")
	keepalive := flag.Int("k", 0, "TCP keepalive interval in seconds (0=disabled)")
	flag.Parse()
	buildVersion := resolvedVersion()

	if *showVersion {
		fmt.Printf("go-ocproxy version: %s\n", buildVersion)
		return nil
	}

	*localIP = cmp.Or(*localIP, os.Getenv("INTERNAL_IP4_ADDRESS"))
	if *localIP == "" {
		return errors.New("internal IP address not set; use -ip or run via OpenConnect")
	}

	*localIP6 = cmp.Or(*localIP6, os.Getenv("INTERNAL_IP6_ADDRESS"))

	validatedMTU, err := mtuFromEnv(*mtu, os.Getenv("INTERNAL_IP4_MTU"))
	if err != nil {
		return err
	}
	*mtu = int(validatedMTU)
	if *localIP6 != "" && *mtu < 1280 {
		return fmt.Errorf("MTU must be at least 1280 when IPv6 is enabled: %d", *mtu)
	}

	var dnsServers []string
	if envDNS := os.Getenv("INTERNAL_IP4_DNS"); envDNS != "" {
		dnsServers = strings.Fields(envDNS)
	}
	if envDNS6 := os.Getenv("INTERNAL_IP6_DNS"); envDNS6 != "" {
		dnsServers = append(dnsServers, strings.Fields(envDNS6)...)
	}

	*dnsDomain = cmp.Or(*dnsDomain, os.Getenv("CISCO_DEF_DOMAIN"))

	listenAddr := "127.0.0.1:" + *socksPort

	log.Printf("[main] -----------------------------------------")
	log.Printf("[main]   go-ocproxy %s", buildVersion)
	log.Printf("[main] -----------------------------------------")
	log.Printf("[main] Listening:     %s (SOCKS5/HTTP)", listenAddr)
	log.Printf("[main] Internal IP:   %s", *localIP)
	if *localIP6 != "" {
		log.Printf("[main] Internal IPv6: %s", *localIP6)
	}
	log.Printf("[main] MTU:           %d", *mtu)
	log.Printf("[main] DNS Servers:   %v", dnsServers)
	if *dnsDomain != "" {
		log.Printf("[main] DNS Domain:    %s", *dnsDomain)
	}
	if *keepalive > 0 {
		log.Printf("[main] TCP Keepalive: %ds", *keepalive)
	}

	ns, err := netstack.New(*localIP, uint32(*mtu), *localIP6)
	if err != nil {
		return fmt.Errorf("initialize netstack: %w", err)
	}
	defer ns.Close()
	if *keepalive > 0 {
		ns.TCPKeepalive = time.Duration(*keepalive) * time.Second
	}

	server := proxy.NewServer(ns, listenAddr, dnsServers, *dnsDomain)
	if err := server.Listen(); err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	ctx, ctxCancel := sigctx.New(context.Background(), server.DumpStats)
	defer ctxCancel()

	tunnel, err := transport.OpenFromEnv()
	if err != nil {
		ctxCancel()
		server.Close(5 * time.Second)
		return fmt.Errorf("open VPN transport: %w", err)
	}
	defer tunnel.Close()

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- server.Serve(ctx) }()
	netstackErrCh := make(chan error, 1)
	go func() { netstackErrCh <- ns.Run(ctx, tunnel) }()

	var componentErr error
	netstackDone := false
	select {
	case err := <-netstackErrCh:
		netstackDone = true
		if !isCleanShutdownErr(err) {
			componentErr = fmt.Errorf("netstack: %w", err)
		}
		log.Printf("[main] netstack exited, shutting down...")
	case err := <-serveErrCh:
		if err != nil {
			componentErr = fmt.Errorf("proxy server: %w", err)
		} else if ctx.Err() == nil {
			componentErr = errors.New("proxy server stopped unexpectedly")
		}
		log.Printf("[main] proxy server exited, shutting down...")
	}
	ctxCancel()
	tunnel.Close()
	server.Close(5 * time.Second)
	if !netstackDone {
		select {
		case <-netstackErrCh:
		case <-time.After(2 * time.Second):
			if componentErr == nil {
				componentErr = errors.New("netstack did not stop after tunnel close")
			}
		}
	}
	log.Printf("[main] shutdown complete")
	return componentErr
}

func mtuFromEnv(fallback int, value string) (uint32, error) {
	mtu := fallback
	if value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("invalid INTERNAL_IP4_MTU %q: %w", value, err)
		}
		mtu = parsed
	}
	if mtu < 576 || mtu > 65535 {
		return 0, fmt.Errorf("MTU must be between 576 and 65535: %d", mtu)
	}
	return uint32(mtu), nil
}

func resolvedVersion() string {
	if version != "" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	var revision string
	modified := false
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		return "devel"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	if modified {
		revision += "-dirty"
	}
	return revision
}

func isCleanShutdownErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, os.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.EBADF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "file already closed") ||
		strings.Contains(msg, "use of closed") ||
		strings.Contains(msg, "bad file descriptor")
}
