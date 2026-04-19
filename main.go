package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/doctor/go-ocproxy/internal/socks"
	"github.com/doctor/go-ocproxy/internal/stack"
)

func main() {
	// 命令行参数
	socksAddr := flag.String("socks", "127.0.0.1:1080", "SOCKS5 listen address")
	localIP := flag.String("ip", "", "Internal IPv4 address (overrides environment)")
	mtu := flag.Int("mtu", 1500, "MTU (overrides environment)")
	flag.Parse()

	// 1. 读取 OpenConnect 环境变量
	envIP := os.Getenv("INTERNAL_IP4_ADDRESS")
	if *localIP == "" {
		*localIP = envIP
	}
	if *localIP == "" {
		// 如果没有环境变量，尝试从参数读取，否则报错
		log.Fatal("Internal IP address not set. Use -ip or run via openconnect.")
	}

	envMTU := os.Getenv("INTERNAL_IP4_MTU")
	if envMTU != "" {
		m, err := strconv.Atoi(envMTU)
		if err == nil {
			*mtu = m
		}
	}

	// 读取 DNS
	dnsServers := []string{}
	envDNS := os.Getenv("INTERNAL_IP4_DNS")
	if envDNS != "" {
		dnsServers = strings.Fields(envDNS)
	}

	log.Printf("go-ocproxy starting...")
	log.Printf("Internal IP: %s", *localIP)
	log.Printf("MTU:         %d", *mtu)
	log.Printf("DNS Servers: %v", dnsServers)

	// 2. 初始化 gVisor 网络栈
	ns, err := stack.NewNetStack(*localIP, uint32(*mtu))
	if err != nil {
		log.Fatalf("Failed to initialize netstack: %v", err)
	}

	// 3. 启动 SOCKS5 服务
	server := socks.NewServer(ns, *socksAddr, dnsServers)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	// 4. 处理退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		os.Exit(0)
	}()

	// 5. 阻塞运行协议栈 I/O
	// 这里将 stdin/stdout 与网络栈对接
	if err := ns.Run(os.Stdin, os.Stdout); err != nil {
		if err != os.ErrClosed && !strings.Contains(err.Error(), "file already closed") {
			log.Fatalf("Netstack runtime error: %v", err)
		}
	}
}
