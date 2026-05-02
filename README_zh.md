# go-ocproxy

[English](README.md) | 简体中文

`go-ocproxy` 是对原版 `ocproxy` 的现代 Go 语言重写。它能与 `openconnect` 协议配合，通过用户态网络协议栈将 VPN 流量转化为本地 SOCKS5 代理，从而避免污染全局路由。

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
- [x] **内网 DNS 转发**：自动识别并利用 VPN 内部 DNS 进行域名解析。
- [x] **自动配置集成**：完美继承 `openconnect` 分配的 IP、MTU 和 DNS 环境变量。
- [x] **稳定流处理**：精确的 IP 数据包边界处理，确保长连接稳定性。

## 🛠️ 编译
需要 Go 1.25 或更高版本。
```bash
cd go-ocproxy
go build -o go-ocproxy
```

## 📖 使用方法
在启动 `openconnect` 时，作为脚本参数运行：
```bash
sudo openconnect \
    --script-tun \
    --script "./go-ocproxy -socks 127.0.0.1:1080" \
    vpn.example.com
```

### 命令行参数
| 参数 | 说明 | 默认值 |
| :--- | :--- | :--- |
| `-D` | SOCKS5 监听端口 | `1080` |
| `-ip` | 手动指定内部 IPv4 地址（通常自动获取） | 无 |
| `-mtu` | 手动指定 MTU 大小（通常自动获取） | `1500` |
| `-o` | 默认 DNS 域名后缀（CISCO_DEF_DOMAIN） | 无 |
| `-k` | TCP keepalive 间隔（秒，0=禁用） | `0` |
| `-V` | 显示版本号 | – |

## 📚 给开发者 / 贡献者

- **行为契约和测试矩阵**：[SPEC.md](SPEC.md)
- **架构、踩坑笔记、贡献指南**：[CLAUDE.md](CLAUDE.md) —— 改 fd / 网络栈代码**之前必读**
- **版本变更记录**：[docs/CHANGELOG.md](docs/CHANGELOG.md)

---
*Created with ❤️ by Gemini CLI.*
