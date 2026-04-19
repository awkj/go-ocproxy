# go-ocproxy

English | [简体中文](README_zh.md)

`go-ocproxy` is a modern, Go-based rewrite of the original `ocproxy`. It works seamlessly with `openconnect` to provide a user-space SOCKS5 proxy for VPN traffic, preventing global routing pollution.

## 🚀 Why go-ocproxy?

### From 80,000 to a few hundred lines
The original `ocproxy` is written in C and carries roughly 80,000 lines of code, primarily because it embeds the entire **lwIP** (Lightweight IP stack) source code.
- **Original (C)**: Manually manages TCP/UDP/IP/DNS protocols, leading to verbose code and complex memory management.
- **Go Version**: Leverages Google's **gVisor (`netstack`)**, a production-grade user-space network stack used in Google Cloud. By using it as a dependency, we achieve better stability and security with a fraction of the code.

### Key Advantages
- **Security**: Memory-safe Go implementation eliminates common C vulnerabilities like buffer overflows.
- **Performance**: High-concurrency support with gVisor's mature TCP/UDP implementation.
- **Smart DNS**: Automatically handles VPN-internal DNS resolution via the tunnel.
- **Self-contained**: Compiles into a single static binary with zero external dependencies.

## ✨ Features
- [x] **SOCKS5 Proxy**: Listens on `127.0.0.1:1080` by default.
- [x] **Internal DNS Forwarding**: Resolves domains using VPN DNS servers automatically.
- [x] **Auto-Config**: Inherits `INTERNAL_IP4_ADDRESS`, `MTU`, and `DNS` from `openconnect` environment variables.
- [x] **Packet Boundary Logic**: Robust handling of IP packet streams for stable long-lived connections.

## 🛠️ Build
Requires Go 1.21+.
```bash
cd go-ocproxy
go build -o go-ocproxy
```

## 📖 Usage
Run it as an `openconnect` script:
```bash
sudo openconnect \
    --script-tun \
    --script "./go-ocproxy -socks 127.0.0.1:1080" \
    vpn.example.com
```

### CLI Arguments
| Argument | Description | Default |
| :--- | :--- | :--- |
| `-socks` | SOCKS5 listen address | `127.0.0.1:1080` |
| `-ip` | Manually specify internal IPv4 address (usually auto-detected) | None |
| `-mtu` | Manually specify MTU (usually auto-detected) | `1500` |

---
*Created with ❤️ by Gemini CLI.*
