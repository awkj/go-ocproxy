# go-ocproxy

[English](README.md) | 简体中文

`go-ocproxy` 是对原版 `ocproxy` 的现代 Go 语言重写。它能与 `openconnect` 协议配合，通过用户态网络协议栈将 VPN 流量转化为本地代理，从而避免污染全局路由。**同一端口同时支持 SOCKS5 与 HTTP 代理**，按首字节自动嗅探协议，浏览器无需区分配置。

## 🚀 为什么选择 go-ocproxy？

### 从 80,000 行到几百行的进化
原版 `ocproxy` 包含约 8 万行代码，主要是因为它内置了完整的 **lwIP** (C 语言轻量级协议栈) 源码。
- **原版 (C)**：需要手动维护底层的 TCP/UDP/IP 协议细节和复杂的内存管理。
- **Go 版本**：利用 Google 开源的 **gVisor (`netstack`)**。gVisor 是用于 Google Cloud 安全沙箱的工业级协议栈。我们将其作为依赖引入，用极简的代码实现了极高的稳定性和安全性。

### 核心优势
- **安全**：Go 语言天然规避了 C 语言常见的缓冲区溢出等安全风险。
- **高性能**：基于 gVisor 成熟的协议实现，处理高并发连接更稳健。
- **智能 DNS**：内置对 VPN 内部 DNS 的自动解析支持，解决内网域名访问难题。
- **零依赖**：编译后为单二进制文件运行，无需额外配置系统库。

## ✨ 核心功能
- [x] **SOCKS5 代理**：默认监听 `127.0.0.1:1080`，转发 TCP 流量。
- [x] **HTTP 代理（同端口）**：同一端口自动嗅探 HTTP 请求，支持 `CONNECT`（HTTPS 隧道）与普通 HTTP 转发（绝对 URI、自动剥离 hop-by-hop 头）。浏览器把 HTTP/HTTPS 代理都填这一个端口即可。
- [x] **内网 DNS 转发**：自动识别并利用 VPN 内部 DNS 进行域名解析。
- [x] **自动配置集成**：完美继承 `openconnect` 分配的 IP、MTU 和 DNS 环境变量。
- [x] **稳定流处理**：精确的 IP 数据包边界处理，确保长连接稳定性。

## 🛠️ 编译
需要最新稳定版 Go（当前为 Go 1.27.1）。
```bash
cd go-ocproxy
go build -o go-ocproxy
```

## 📖 使用方法
在启动 `openconnect` 时，作为脚本参数运行：
```bash
sudo openconnect \
    --script-tun \
    --script "./go-ocproxy -D 1080" \
    vpn.example.com
```

监听端口同时接受 SOCKS5 和 HTTP 代理请求。浏览器配置示例（macOS 系统代理）：
- HTTP 代理：`127.0.0.1:1080`
- HTTPS 代理：`127.0.0.1:1080`
- SOCKS 代理：`127.0.0.1:1080`

Windows 上的 OpenConnect 不提供 `--script-tun`。外部 libopenconnect helper 可通过
`VPN_UDP_PEER=127.0.0.1:<port>` 启动 go-ocproxy，使用 connected loopback UDP
保持“一 datagram 一 IP 包”的边界；非 loopback 地址会被拒绝。helper 必须同时设置随机
`VPN_UDP_TOKEN`，并在收包前校验首个 datagram 与该 token 完全一致。

### 命令行参数
| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-D` | SOCKS5/HTTP 代理监听端口（同端口嗅探） | `1080` |
| `-ip` | 手动指定内部 IPv4 地址（通常自动获取） | 无 |
| `-ip6` | 手动指定可选的内部 IPv6 地址 | 无 |
| `-mtu` | 手动指定 MTU 大小（通常自动获取） | `1500` |
| `-o` | DNS 默认域名后缀（覆盖 `CISCO_DEF_DOMAIN`） | 无 |
| `-k` | TCP keepalive 间隔（秒），0 关闭 | `0` |
| `-V` | 打印版本并退出 | — |

## 📚 给开发者 / 贡献者

- **行为契约和测试矩阵**：[SPEC.md](SPEC.md)
- **架构、踩坑笔记、贡献指南**：[AGENTS.md](AGENTS.md) —— 改 fd / 网络栈代码**之前必读**
- **版本变更记录**：[docs/CHANGELOG.md](docs/CHANGELOG.md)

---
*Created with ❤️ by Gemini CLI.*
