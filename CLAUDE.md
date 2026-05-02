# CLAUDE.md

> 这份文档面向 **AI 开发助手（Claude Code 等）和长期维护者**，是 README 的补集而非重复。
> 用户视角的"它是什么 / 怎么装 / 怎么用"在 [README.md](README.md) / [README_zh.md](README_zh.md)。
> 行为契约和测试矩阵在 [SPEC.md](SPEC.md)。
> 这里只放**读代码读不出来的东西**：设计意图、踩过的坑、不变量、贡献约定。

## 项目定位（一句话）

`openconnect --script-tun` 把 VPN IP 包通过 socketpair 喂给本进程；本进程内嵌 gVisor 用户态网络栈，对外暴露 SOCKS5（默认 `:1080`）。**本质是把 VPN 流量"翻译"成本机可路由的 SOCKS5，免去全局路由污染。**

## 什么时候看哪份文档

| 你想做的事 | 看哪 |
|---|---|
| 装一下用一下 | README |
| 看支持哪些协议 / CLI 参数 | README |
| 改代码、写测试 | **CLAUDE.md（本文）+ SPEC.md** |
| 看具体行为契约（如 S-OUT-2 该怎么处理 ENOBUFS） | SPEC.md |
| 看历史变更 / 升级注意 | docs/CHANGELOG.md |
| 找上游 C 版 ocproxy 的对应行为 | SPEC.md 附录 A |

## 架构（最简）

```
                    ┌──────────────────────────────────────┐
openconnect         │       go-ocproxy 进程                 │
  --script-tun  ◄══╪═══►  AF_UNIX SOCK_DGRAM (一端 fd)      │
                    │            │                          │
                    │            ▼                          │
                    │   stack/stack.go                      │
                    │   ├─ inbound  : VPN → gVisor          │
                    │   └─ outbound : gVisor → VPN          │
                    │            │                          │
                    │            ▼                          │
                    │   gVisor netstack (TCP/UDP/IP)        │
                    │            │                          │
                    │            ▼                          │
                    │   socks/socks.go (SOCKS5 :1080)  ◄──── 浏览器 / curl
                    └──────────────────────────────────────┘
```

- **入口**：`main.go` 解析 flag/env，创建 `NetStack`，跑 `socks.Server` + `ns.Run()`
- **stack/**：gVisor 集成，封 inbound/outbound IP 包搬运 + VPN 健康检查
- **socks/**：SOCKS5 服务、DNS 解析（含 DNS-over-TCP 走隧道，绕开 `--script-tun` 下 UDP DNS 偶发丢包）

## 关键不变量与坑（**改代码前必读**）

> 这是过去踩坑沉淀下来的"看代码看不出来"的部分。每条都对应过一个真实 bug 或反直觉行为。

### 1. AF_UNIX SOCK_DGRAM 一次读必须读完整包

`openconnect` `tun.c` 用 `socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)`。SOCK_DGRAM 语义：每次 `read()` 返回**一个完整 IP 包**；buffer 比 datagram 小则**多余字节被内核丢弃**。

**不要分次读 header / payload。**inbound 必须一次性 `Read` 到 ≥ 65535 字节 buffer。

### 2. PacketBuffer 引用计数易泄漏

gVisor 的 `*PacketBuffer` 用引用计数管理。`channel.Endpoint.ReadContext` 返回的 pkt 引用计数 = 1，**调用方必须 `DecRef`**；`InjectInbound` 内部会 `IncRef`，调用方仍需对自己那份初始引用 `DecRef`。漏 `DecRef` 一个包就泄漏一个池槽位，长跑高吞吐场景会吃光内存。

`pkt.ToBuffer()` 返回的 `Buffer` 是临时副本，`buf.Release()` 释放副本，**与 pkt 本体引用计数完全是两码事**。

### 3. 非阻塞 fd 陷阱（v1.2 修复的核心）

`net.FileConn(fd)` 会 dup fd 并把 dup 的新 fd 强制设为 `O_NONBLOCK`（Go runtime poller 的硬性要求）。**坑点**：dup 出的两个 fd 共享同一个 file description，O_NONBLOCK **是 file description 级别的标志位，不是 fd 级别的** —— 所以 dup 后**原 fd 也变成非阻塞**。

如果代码里同时存在：
- `inputConn := net.FileConn(input)`（或类似操作）
- `output.Write(...)` 用裸 `*os.File`

裸 `Write` 不会经 Go runtime poller 等可写，遇到 EAGAIN 直接返回错误。**症状**：高吞吐场景（≥ 10MB 上传）卡死在 1%，因为大量包被当作 transient 丢弃。

**修复约定**：所有对 VPN fd 的 IO 必须通过同一个 `net.Conn`（`vpnConn`），不要走裸 `*os.File`。

### 4. macOS ENOBUFS 不能当 fatal

macOS 上 AF_UNIX SOCK_DGRAM 在高吞吐时会因系统 mbuf 池**暂时耗尽**返回 `ENOBUFS`。这是 transient 错误，但 Go runtime poller **不会自动重试** ENOBUFS（它只重试 EAGAIN）。

- ❌ 当 fatal → 整个 SOCKS5 服务挂掉
- ❌ 当 transient 静默丢包 → TCP 触发重传，重传又遇 ENOBUFS，连接事实停滞
- ✅ 用 `writeOutboundWithRetry` 退避重试（1ms→32ms 上限，最多 10 次），实在不行才丢一个包但**绝不退出 goroutine**

详见 `stack/stack.go` 的 `writeOutboundWithRetry`。

### 5. macOS AF_UNIX 默认 SO_SNDBUF 极小

约 8 KiB，遇到 1500B IP 包瞬间灌满。启动时显式调大 `SO_SNDBUF` / `SO_RCVBUF` 到 1 MiB **必须在 `net.FileConn` 之前**对原始 fd 操作（FileConn 把 fd 设非阻塞之后再调虽然也行，但语义清晰起见放前面）。

### 6. socketpair 对端死亡检测

AF_UNIX SOCK_DGRAM 没有 TCP 那种 EOF 概念——对端 `close()` 后，本端的 `Read` 不一定立刻返回错误（macOS 上实测会一直阻塞）。inbound `Read` 退出路径不可靠。

解决：独立 goroutine 每秒 `getpeername()` 探测，对端关闭后会返回 `ENOTCONN`。**不要**用 0 字节 write 探（某些平台是 no-op），也不要发真正的探测包（污染 VPN 流量）。

### 7. SOCKS5 收到域名时的 DNS 解析

`--script-tun` 模式下，UDP DNS 偶发丢包。go-ocproxy 在 SOCKS5 收到域名请求时改用**手写 DNS-over-TCP** 经 gVisor 隧道查询。详见 `socks/socks.go` 的 DNS 部分。

### 8. channel.Endpoint 队列大小 ≥ 1024

`channel.New(1024, mtu, "")` 是经过实测的下限。256 在高并发下会把 inbound packet 队列灌满导致丢包。

## 错误处理分层（出向写入）

```
gVisor 出包
   ▼
writeOutboundWithRetry(ctx, vpnConn, data)
   │
   ├─ 立即成功                  → 返回 nil
   ├─ ctx cancel / Deadline     → 返回 ctx.Err() 或 ErrDeadlineExceeded（调用方退出）
   ├─ isFatalWriteErr (EPIPE…)  → 立即返回 fatal err（调用方退出 + 通知 main）
   └─ transient (ENOBUFS…)      → 退避 1ms / 2ms / 4ms / ... / 32ms × 5
                                  ├─ 期间任何一次成功 → 返回 nil
                                  ├─ 期间 ctx done   → 返回 ctx.Err()
                                  └─ 全部失败        → 返回 transient err（调用方丢包但**不退出**，按秒聚合日志）
```

测试约定：每条分支至少一个 unit test（见 `stack/stack_test.go` 的 `TestWriteOutboundWithRetry_*`）。

## 调试

| 想看什么 | 怎么做 |
|---|---|
| 实时 stats（连接数、字节数、SOCKS5 队列） | `kill -USR1 <pid>` |
| 详细日志 | 直接看 stderr，关键前缀 `[main]` `[stack]` `[socks]` `[health]` |
| 出向是否在丢包 | 看 stderr 是否有 `[stack] outbound dropped N pkt in last ...` |
| 进程是否死了 | `[main] netstack exited, shutting down...` |

## 测试

```bash
go test ./...           # 单元 + 集成
go test ./stack/ -v     # 看每个 case
go test ./... -race     # 数据竞争检测
```

测试设计原则：
- **不依赖真实 openconnect**：用 `socketpair(AF_UNIX, SOCK_DGRAM)` 模拟 VPN fd
- **不依赖真实网络**：用 `scriptedConn` mock `net.Conn`，按脚本返回错误序列
- **测试时退避归零**：`withFastRetry(t)` 把 `outboundInitialDelay` / `outboundMaxDelay` 设为 0，单测 < 1ms

新增行为契约时**先写到 SPEC.md**（编号 S-XXX-N），再写测试，再实现 —— 三件套对齐。

## 构建

需要 Go 1.25+（gVisor 最新版要求）。

```bash
go build -trimpath -ldflags="-s -w" -o go-ocproxy
```

`-trimpath` 去掉编译机绝对路径（可重现构建）；`-ldflags="-s -w"` 剥符号表 + DWARF，gVisor 依赖很大，体积可降 25–30%。

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
- d-bar（macOS 菜单栏 VPN 客户端）是本项目主要消费者；d-bar 的 `scripts/build-static-binaries.sh` 会从本仓库 master `git clone --reset --hard` 拉最新代码
