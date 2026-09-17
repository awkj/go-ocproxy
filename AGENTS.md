# AGENTS.md

> 这份文档面向 **AI 开发助手和长期维护者**，是 README 的补集而非重复。
> 用户视角的"它是什么 / 怎么装 / 怎么用"在 [README.md](README.md) / [README_zh.md](README_zh.md)。
> 行为契约和测试矩阵在 [SPEC.md](SPEC.md)。
> 这里只放**读代码读不出来的东西**：设计意图、踩过的坑、不变量、贡献约定。

## 项目定位（一句话）

本进程从 OpenConnect transport 接收 VPN IP 包，内嵌 gVisor 用户态网络栈，并对外暴露 SOCKS5 / HTTP 代理（默认 `:1080`）。macOS transport 是 `--script-tun` 的 socket fd，Windows transport 是外部 libopenconnect helper 提供的 connected loopback UDP。**本质是把 VPN 流量“翻译”成本机应用可显式使用的代理，免去全局路由污染。**

## 什么时候看哪份文档

| 你想做的事 | 看哪 |
|---|---|
| 装一下用一下 | README |
| 看支持哪些协议 / CLI 参数 | README |
| 改代码、写测试 | **AGENTS.md（本文）+ SPEC.md** |
| 看具体行为契约（如 S-OUT-2 该怎么处理 ENOBUFS） | SPEC.md |
| 看历史变更 / 升级注意 | docs/CHANGELOG.md |
| 找上游 C 版 ocproxy 的对应行为 | SPEC.md 附录 A |

## 架构（最简）

```
OpenConnect transport
  ├─ macOS: VPNFD / AF_UNIX SOCK_DGRAM
  └─ Windows: VPN_UDP_PEER / connected loopback UDP
                         │
                         ▼
                 netstack/netstack.go
                 ├─ inbound  : VPN → gVisor
                 └─ outbound : gVisor → VPN
                         │
                         ▼
                 gVisor netstack
                         │
                         ▼
                 proxy/socks5.go + http.go + dns.go
                 SOCKS5 / HTTP :1080 ← browser / curl
```

- **入口**：`main.go` 解析 flag/env，创建 `NetStack`（支持可选 IPv6 双栈），跑 `proxy.Server` + `ns.Run()`
- **transport/**：平台 transport 适配；macOS 读取 `VPNFD`，Windows 建立 loopback UDP
- **netstack/**：gVisor 集成（IPv4 + 可选 IPv6），负责 IP 包搬运和平台健康检查
- **proxy/**：`server.go` 管生命周期，`socks5.go` / `http.go` 管协议，`dns.go` 管 DNS（A + 可选 AAAA 回退，含 DNS-over-TCP 走隧道）

## 支持平台与边界

- 发布目标只有 **macOS arm64** 和 **Windows amd64**。
- macOS 通过 `VPNFD` 接收 OpenConnect `--script-tun` 的 AF_UNIX datagram fd。
- Windows 通过 `VPN_UDP_PEER` 接收外部 libopenconnect helper 提供的 connected loopback UDP；helper 必须设置随机 `VPN_UDP_TOKEN` 并校验首个 datagram 与 token 完全一致。
- 本仓库保持产品中立：协议名、环境变量、日志和文档不得包含具体消费方名称。消费方专属的进程编排、分流规则和 UI 不进入本仓库。

## 关键不变量与坑（**改代码前必读**）

> 这是过去踩坑沉淀下来的"看代码看不出来"的部分。每条都对应过一个真实 bug 或反直觉行为。

### 1. AF_UNIX SOCK_DGRAM 一次读必须读完整包

`openconnect` `tun.c` 用 `socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)`。SOCK_DGRAM 语义：每次 `read()` 返回**一个完整 IP 包**；buffer 比 datagram 小则**多余字节被内核丢弃**。

**不要分次读 header / payload。**inbound 必须一次性 `Read` 到 ≥ 65535 字节 buffer。

### 2. PacketBuffer 引用计数易泄漏

gVisor 的 `*PacketBuffer` 用引用计数管理。`channel.Endpoint.ReadContext` 返回的 pkt 引用计数 = 1，**调用方必须 `DecRef`**。`InjectInbound` 是同步调用且不会替调用方保留引用，因此它返回后也必须释放调用方持有的唯一引用。漏 `DecRef` 一个包就泄漏一个池槽位，长跑高吞吐场景会吃光内存。

`pkt.ToBuffer()` 返回的 `Buffer` 是临时副本，`buf.Release()` 释放副本，**与 pkt 本体引用计数完全是两码事**。

### 3. Transport 必须是单一双向 `net.Conn`

macOS 只在 `transport` 中把 `VPNFD` 转换一次为 `net.Conn`，随后关闭继承的原 fd；Windows 直接使用 connected `*net.UDPConn`。`NetStack.Run` 只接收一个双向 `net.Conn`，不能重新引入 input/output 两套句柄或裸 `*os.File.Write`。否则 `net.FileConn` 的 dup/O_NONBLOCK 语义会造成 EAGAIN 丢包，并让读写实际落在不同对象上。

### 4. macOS ENOBUFS 不能当 fatal

macOS 上 AF_UNIX SOCK_DGRAM 在高吞吐时会因系统 mbuf 池**暂时耗尽**返回 `ENOBUFS`。这是 transient 错误，但 Go runtime poller **不会自动重试** ENOBUFS（它只重试 EAGAIN）。

- ❌ 当 fatal → 整个 SOCKS5 服务挂掉
- ❌ 当 transient 静默丢包 → TCP 触发重传，重传又遇 ENOBUFS，连接事实停滞
- ✅ 用 `writeOutboundWithRetry` 退避重试（1ms→32ms 上限，最多 10 次），实在不行才丢一个包但**绝不退出 goroutine**

详见 `netstack/netstack.go` 的 `writeOutboundWithRetry`。

### 5. macOS AF_UNIX 默认 SO_SNDBUF 极小

约 8 KiB，遇到 1500B IP 包瞬间灌满。`NetStack.Run` 通过 `net.UnixConn` / `net.UDPConn` 的 portable buffer setter 请求把读写缓冲调到 1 MiB；不要新增平台 syscall 分支。

### 6. socketpair 对端死亡检测

AF_UNIX SOCK_DGRAM 没有 TCP 那种 EOF 概念——对端 `close()` 后，本端的 `Read` 不一定立刻返回错误（macOS 上实测会一直阻塞）。inbound `Read` 退出路径不可靠。

解决：独立 goroutine 每秒 `getpeername()` 探测，对端关闭后会返回 `ENOTCONN`。**不要**用 0 字节 write 探（某些平台是 no-op），也不要发真正的探测包（污染 VPN 流量）。

### 7. SOCKS5 收到域名时的 DNS 解析

`--script-tun` 模式下，UDP DNS 偶发丢包。go-ocproxy 在 SOCKS5 收到域名请求时优先查询 UDP，响应截断或失败时通过 gVisor 隧道回退 DNS-over-TCP。详见 `proxy/dns.go`。

### 8. channel.Endpoint 队列大小 ≥ 1024

`channel.New(1024, mtu, "")` 是经过实测的下限。256 在高并发下会把 inbound packet 队列灌满导致丢包。

### 9. IPv6 是可选的附加能力

gVisor 栈始终注册 IPv4 + IPv6 协议，但只有当 `INTERNAL_IP6_ADDRESS` 非空时才向 NIC 添加 IPv6 地址和路由。`NetStack.HasIPv6` 控制 DNS 是否查 AAAA 记录。**不配置 IPv6 时行为必须与旧版本完全一致**——这是向后兼容的硬性要求。

入站包分发按 IP 版本号（首字节高 4 位）决定走 `ipv4.ProtocolNumber` 还是 `ipv6.ProtocolNumber`，非 4/6 的包丢弃。

### 10. Windows UDP transport 必须校验 token

`VPN_UDP_PEER` 只接受 loopback + 非零端口，并要求同时提供 `VPN_UDP_TOKEN`。
进程把 token 原样作为首个 datagram 发送，helper 精确校验后才能接收 IP 包；token
最长 128 字节。token 属于每次启动会话，不能使用消费方名称或固定 secret。

## 错误处理分层（出向写入）

```
gVisor 出包
   ▼
writeOutboundWithRetry(ctx, vpnConn, data)
   │
   ├─ 立即成功                  → 返回 nil
   ├─ ctx cancel / Deadline     → 返回 ctx.Err() 或 ErrDeadlineExceeded（调用方退出）
   ├─ isFatalWriteErr (EPIPE…)  → 立即返回 fatal err（调用方退出 + 通知 main）
   └─ transient (ENOBUFS…)      → 退避 1ms / 2ms / 4ms / ... / 32ms，最多 10 次写入
                                  ├─ 期间任何一次成功 → 返回 nil
                                  ├─ 期间 ctx done   → 返回 ctx.Err()
                                  └─ 全部失败        → 返回 transient err（调用方丢包但**不退出**，按秒聚合日志）
```

测试约定：每条分支至少一个 unit test（见 `netstack/netstack_darwin_test.go` 的 `TestWriteOutboundWithRetry_*`）。

## 调试

| 想看什么 | 怎么做 |
|---|---|
| macOS 实时 stats（连接数、字节数、SOCKS5 队列） | `kill -USR1 <pid>`；Windows 不支持 SIGUSR1 |
| 详细日志 | 直接看 stderr，关键前缀 `[main]` `[netstack]` `[socks]` `[health]` |
| 出向是否在丢包 | 看 stderr 是否有 `[netstack] outbound dropped N pkt in last ...` |
| 进程是否死了 | `[main] netstack exited, shutting down...` |

## 测试

```bash
go test ./...           # 单元 + 集成
go test ./netstack/ -v  # 看每个 case
go test ./... -race     # 数据竞争检测
```

测试设计原则：
- **不依赖真实 openconnect**：macOS/Unix 路径用 `socketpair(AF_UNIX, SOCK_DGRAM)` 模拟 VPN fd；Windows transport 用 loopback UDP listener
- **不依赖真实网络**：用 `scriptedConn` mock `net.Conn`，按脚本返回错误序列
- **测试时退避归零**：`withFastRetry(t)` 把 `outboundInitialDelay` / `outboundMaxDelay` 设为 0，单测 < 1ms

新增行为契约时**先写到 SPEC.md**（编号 S-XXX-N），再写测试，再实现 —— 三件套对齐。

## 构建

始终使用最新稳定版 Go；当前基线是 Go 1.27.1。CI 使用 `go-version: stable`，`go.mod` 记录当前已验证的稳定补丁版本。

```bash
go build -trimpath -ldflags="-s -w" -o go-ocproxy
```

`-trimpath` 去掉编译机绝对路径（可重现构建）；`-ldflags="-s -w"` 剥符号表 + DWARF，gVisor 依赖很大，体积可降 25–30%。

源码中的版本变量没有固定值：普通本地构建优先读取 Go 嵌入的 VCS commit，无法读取时才显示 `devel`。消费方从 `master` 构建时应通过 `-X main.version=<commit>` 注入精确 commit；正式 `v*` tag 发布时由 GoReleaser 注入 tag。

`.goreleaser.yaml` 只服务于 GitHub 的 `v*` tag 发布：构建 macOS arm64 的 `tar.gz` 和 Windows amd64 的 `zip`，并注入发布版本。普通 `go build`、测试和消费方的 `master` 构建都不依赖 GoReleaser。

## 升级 gvisor 依赖（**踩过坑**）

gvisor 是 bazel 项目，**master 分支的源码无法直接被 `go build` 使用**：
- 大量 `*_mutex.go` / `*_refs.go` / `*_state_autogen.go` 是 bazel 从 `.tmpl` 模板生成的，git 不入库
- 部分 `_test.go`（如 `pkg/tcpip/stack/bridge_test.go`）用了 `package bridge_test` 这种声明，bazel 当独立 build target 没问题，但违反 Go 目录-包规则（同目录主包是 `stack`，外部测试包必须叫 `stack_test`），`go build` 直接报 `found packages stack and bridge in ...`

gvisor 团队为此维护了一个独立的 `go` 分支：bazel 跑完代码生成、剥掉 `_test.go` 和 `BUILD` 文件之后 push 上去专供 Go module 用户。

**所以不要用 `go get -u gvisor.dev/gvisor`** —— 它会从 master 拿最新 commit 然后炸。正确做法：

```bash
# 1. 拿 go 分支最新 commit hash
GVISOR_COMMIT=$(curl -s "https://api.github.com/repos/google/gvisor/branches/go" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['commit']['sha'][:12])")

# 2. 显式指定 commit 升级
go get gvisor.dev/gvisor@$GVISOR_COMMIT
go mod tidy

# 3. 验证拉到的是 go 分支的 zip：应有 *_mutex.go，没有 _test.go / BUILD
ls $(go env GOMODCACHE)/gvisor.dev/gvisor@*/pkg/tcpip/stack/ | grep -E '_mutex\.go|_test\.go|^BUILD$'
```

## 提交规范

- 中文 commit message OK，建议 `<type>: <subject>`，type 用 `fix` / `feat` / `refactor` / `docs` / `test` / `chore`
- bug fix 必须**同时**：
  1. 在 `SPEC.md` 里写明（或更新）行为规格
  2. 在 `docs/CHANGELOG.md` 的 `[Unreleased]` 记一笔
  3. 加回归测试（即便只能 mock）
- 改 fd / 网络栈相关代码时，本文档"关键不变量与坑"章节是必读 checklist

## 上游关系

- **本项目是 awkj/go-ocproxy**，是原版 [`cernekee/ocproxy`](https://github.com/cernekee/ocproxy)（C 版）的 Go 重写
- 行为差异表见 `SPEC.md` 附录 A
- C 版 ~80K LOC（嵌 lwIP），本项目几百 LOC（用 gVisor netstack 作依赖）
- `master` 是消费方构建使用的唯一源码真相；平台支持必须先在本仓库合入测试和规格，消费方不得长期维护源码补丁副本
