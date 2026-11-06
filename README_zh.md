# go-ocproxy

[English](README.md) | 简体中文

**基于 gVisor 的用户态网络代理，将 IP 数据包通道转换为 SOCKS5 / HTTP 代理。**

`go-ocproxy` 用 Go 实现代理协议与 IP 网络栈之间的转换。应用通过本地代理发起
TCP / UDP 请求，gVisor netstack 处理网络协议，再通过外部提供的双向通道收发 IP 数据包。

**SOCKS5、HTTP 转发和 HTTPS CONNECT 共用一个端口，默认 `127.0.0.1:1080`。**
代理侧无需创建系统 TUN 接口，也不修改系统路由或 DNS；外部程序负责建立和维护数据包通道。

```text
应用 ── SOCKS5 / HTTP ── go-ocproxy（gVisor netstack）── IP 数据包通道 ── 目标网络
```

## 可以用它做什么

- 将已有的 VPN 数据包通道接入本地代理，供浏览器、命令行工具和其他应用使用。
- 在自己的网络工具中复用用户态 TCP/IP 栈，通过独立进程处理代理请求。
- 为能够收发 IP 数据包的外部程序提供 SOCKS5 / HTTP 访问入口。

OpenConnect 的 `--script-tun` 是一种现成的接入方式。其他程序也可以适配当前的
数据包通道与配置约定：Linux / macOS 使用继承的 Unix datagram socket，Windows 使用
loopback UDP。每个数据报必须承载一个完整 IP 包，具体要求见下方接入说明。

## 功能

| 能力 | 说明 |
| --- | --- |
| 单端口代理 | 同时接受 SOCKS5、HTTP 转发和 HTTPS CONNECT，自动识别协议 |
| SOCKS5 TCP / UDP | 支持 CONNECT 和 UDP ASSOCIATE；UDP 需应用支持，不支持 SOCKS5 分片重组 |
| 域名解析 | 通过数据包通道查询配置的 DNS；支持域名后缀、缓存和 DNS-over-TCP 回退 |
| IPv4 / 可选 IPv6 | 默认 IPv4；配置 IPv6 地址后启用双栈 |
| 用户态网络栈 | 使用 gVisor netstack；go-ocproxy 可编译为单个二进制文件 |

代理固定监听本机 IPv4 回环地址 `127.0.0.1`，不提供代理认证或远程监听配置。

## 平台支持

| 平台 | 发布构建目标 | 接入方式 |
| --- | --- | --- |
| Linux | amd64 | 继承的 Unix datagram socket（`VPNFD`） |
| macOS | arm64 | 继承的 Unix datagram socket（`VPNFD`） |
| Windows | amd64 | connected loopback UDP（`VPN_UDP_PEER`） |

## 获取程序

从 [Releases](https://github.com/awkj/go-ocproxy/releases) 获取已发布的平台包，或从源码编译。

源码构建的 Go 版本要求见 [go.mod](go.mod)。在仓库根目录执行：

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o go-ocproxy .
```

## 接入数据包通道

### Linux / macOS：继承的 Unix socket

启动方需创建已连接的 `AF_UNIX/SOCK_DGRAM` 双向通道，将其中一个文件描述符继承给
子进程，并通过 `VPNFD` 指定描述符编号。双方按“一数据报一完整 IP 包”收发，
启动方负责把通道另一端接到目标网络，并提供地址、MTU 和 DNS 配置。

仅设置环境变量或启动 go-ocproxy 不会建立数据包通道。

#### 示例：配合 OpenConnect

先安装 OpenConnect，再在 `go-ocproxy` 所在目录执行，将网关替换为自己的地址：

```bash
openconnect \
  --script-tun \
  --script './go-ocproxy -D 1080' \
  vpn.example.com
```

按 OpenConnect 提示完成认证，并保持该进程运行。`--script-tun` 将 VPN 数据包直接交给
`go-ocproxy`，后者读取 VPN 分配的地址、MTU 和 DNS 信息，并启动本地代理。

### Windows：loopback UDP

外部程序需提供 IPv4 loopback UDP 端点，与 go-ocproxy 交换 IP 数据包，
并在启动 go-ocproxy 时传入地址、MTU、DNS 等配置，以及：

| 环境变量 | 要求 |
| --- | --- |
| `VPN_UDP_PEER` | 外部程序的 IPv4 loopback UDP 地址，如 `127.0.0.1:12345`，端口必须非零 |
| `VPN_UDP_TOKEN` | 每次会话随机生成的非空 token，最长 128 字节 |

go-ocproxy 会将 token 原样作为首个 UDP 数据报发送，外部程序必须先精确校验 token，
再交换 VPN 数据包。之后每个 UDP 数据报承载一个完整 IP 包。外部程序还需监督子进程，
在通道关闭或自身退出时终止 go-ocproxy。

例如，基于 libopenconnect 的 helper 可以负责 VPN 连接，再通过该通道接入代理。
本仓库不包含该 helper；Windows 版 OpenConnect 命令行不提供 `--script-tun`。

## 使用代理

外部程序接好数据包通道并启动 go-ocproxy 后，在另一个终端中执行。
将示例地址替换为该通道可达的目标服务：

```bash
# SOCKS5：由代理解析目标域名
curl --proxy socks5h://127.0.0.1:1080 https://service.example.com

# HTTP 代理：HTTPS 请求通过 CONNECT 建立隧道
curl --proxy http://127.0.0.1:1080 https://service.example.com
```

浏览器或应用的 HTTP、HTTPS、SOCKS5 代理均可填写 `127.0.0.1:1080`。
发给本代理的请求通过数据包通道访问目标；选择哪些应用或域名使用代理，由应用、
PAC 或上层工具配置。

SOCKS5 使用目标域名时，启用“通过代理解析 DNS”，命令行中使用 `socks5h://`。
若未配置 DNS 服务器，go-ocproxy 使用系统 DNS 解析。

## 配置

启动方通过环境变量提供网络配置，部分选项也可用命令行参数设置。
配合 OpenConnect 时，这些环境变量由 OpenConnect 提供。

| 参数 | 作用 | 默认值 / 来源 |
| --- | --- | --- |
| `-D <port>` | SOCKS5 / HTTP 监听端口 | `1080` |
| `-ip <address>` | 网络栈 IPv4 地址 | `INTERNAL_IP4_ADDRESS`，必需 |
| `-ip6 <address>` | 网络栈 IPv6 地址 | `INTERNAL_IP6_ADDRESS`，可选 |
| `-mtu <bytes>` | 未提供环境变量时使用的 MTU | `1500`；`INTERNAL_IP4_MTU` 优先 |
| `-o <domain>` | 裸主机名解析失败后尝试的域名后缀 | `CISCO_DEF_DOMAIN` |
| `-k <seconds>` | TCP keepalive 间隔 | `0`，关闭 |
| `-V` | 打印版本并退出 | — |

DNS 服务器取自 `INTERNAL_IP4_DNS` 和 `INTERNAL_IP6_DNS`，多个地址用空白分隔。
Linux / macOS 还需由启动方继承传入有效的 `VPNFD`；地址配置与数据包通道必须同时提供。

## 项目与开发

本项目是 [ocproxy](https://github.com/cernekee/ocproxy) 的 Go 重写，使用 gVisor netstack
实现用户态网络协议处理，保留与 OpenConnect 的接入约定。

- [SPEC.md](SPEC.md)：行为契约、与原版的差异及测试矩阵。
- [AGENTS.md](AGENTS.md)：架构、维护约定和实现注意事项。
- [docs/CHANGELOG.md](docs/CHANGELOG.md)：版本变更记录。

## 许可证

采用 [MIT 许可证](LICENSE)，允许商用、修改和再分发，需保留版权与许可声明。
第三方依赖仍遵循各自的许可证，包括 gVisor 的 Apache-2.0 许可证。
