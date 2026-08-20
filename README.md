

# go-ocproxy

English | [简体中文](README_zh.md)

`go-ocproxy` is a modern, Go-based rewrite of the original `ocproxy`. It works seamlessly with `openconnect` to provide a user-space proxy for VPN traffic, preventing global routing pollution. **A single port serves both SOCKS5 and HTTP proxy** — the protocol is auto-detected from the first byte, so browsers can use the same address for HTTP, HTTPS, and SOCKS.

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
- [x] **HTTP Proxy (same port)**: Auto-sniffs HTTP requests on the same port. Supports `CONNECT` (HTTPS tunneling) and absolute-URI HTTP forwarding with automatic hop-by-hop header stripping.
- [x] **Internal DNS Forwarding**: Resolves domains using VPN DNS servers automatically.
- [x] **Auto-Config**: Inherits `INTERNAL_IP4_ADDRESS`, `MTU`, and `DNS` from `openconnect` environment variables.
- [x] **Packet Boundary Logic**: Robust handling of IP packet streams for stable long-lived connections.

## 🛠️ Build
Requires the latest stable Go release (currently Go 1.26.5).
```bash
cd go-ocproxy
go build -o go-ocproxy
```

## 📖 Usage
Run it as an `openconnect` script:
```bash
sudo openconnect \
    --script-tun \
    --script "./go-ocproxy -D 1080" \
    vpn.example.com
```

The listening port accepts both SOCKS5 and HTTP proxy connections. In your browser/system proxy settings, point HTTP, HTTPS, and SOCKS all at `127.0.0.1:1080`.

On Windows, OpenConnect does not expose `--script-tun`. An external libopenconnect
helper can start go-ocproxy with a connected loopback UDP transport in
`VPN_UDP_PEER=127.0.0.1:<port>`. The transport preserves one IP packet per datagram;
non-loopback peers are rejected. Helpers must also set a random `VPN_UDP_TOKEN`
and validate that exact token as the initial datagram before accepting packets.

### CLI Arguments
| Argument | Description | Default |
| :--- | :--- | :--- |
| `-D` | SOCKS5/HTTP proxy listen port (same port, auto-sniffed) | `1080` |
| `-ip` | Manually specify internal IPv4 address (usually auto-detected) | None |
| `-ip6` | Manually specify internal IPv6 address (usually auto-detected) | None |
| `-mtu` | Manually specify MTU (usually auto-detected) | `1500` |
| `-o` | Default DNS domain suffix (overrides `CISCO_DEF_DOMAIN`) | None |
| `-k` | TCP keepalive interval in seconds (0 to disable) | `0` |
| `-V` | Print version and exit | — |

## 📚 For Developers / Contributors

- **Behavior contract & test matrix**: [SPEC.md](SPEC.md)
- **Architecture, gotchas, contribution guide**: [AGENTS.md](AGENTS.md) — read this **before changing fd / netstack code**
- **Version history**: [docs/CHANGELOG.md](docs/CHANGELOG.md)

---
*Created with ❤️ by Gemini CLI.*
