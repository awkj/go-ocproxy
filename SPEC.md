# go-ocproxy 行为规格说明

本文档定义 go-ocproxy 各模块的预期行为，作为实现和测试的唯一参照。
每条规格标注 `[TESTABLE]` 表示可编写自动化测试验证，`[MANUAL]` 表示需人工或集成环境验证。

---

## 1. stack — 网络栈 I/O（`internal/stack/stack.go`）

### 1.1 Inbound：VPN → gVisor

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-IN-1 | 每次 `input.Read()` 必须用 ≥65535 字节的 buffer 一次读取完整 datagram。禁止分多次读（如先读 header 再读 payload）。 | [TESTABLE] 构造 SOCK_DGRAM socketpair，写入完整 IP 包，验证 Read 端一次拿到全部字节 |
| S-IN-2 | 读到的字节数 < 20 时丢弃该包（不够 IPv4 header），不报错，继续读下一个。 | [TESTABLE] 写入 10 字节短包，验证不触发错误，后续正常包仍能处理 |
| S-IN-3 | `input.Read()` 返回 error 时，`Run()` 立即返回该 error。 | [TESTABLE] 关闭 socketpair 写端，验证 Run 返回 io.EOF 或 os.ErrClosed |
| S-IN-4 | 每个入向包必须拷贝到独立 `[]byte` 后再注入 gVisor，不能复用同一 buffer 指针。 | [TESTABLE] 连续写入两个不同内容的包，验证 gVisor 收到的两个包内容各自正确 |

### 1.2 Outbound：gVisor → VPN

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-OUT-1 | 出向 goroutine 遇到**致命写错误**（EPIPE / EBADF / ECONNRESET / ENOTCONN / io.ErrClosedPipe / os.ErrClosed）时退出，并**通知主循环**使 `Run()` 尽快返回。不能只退出 goroutine 而让 `Run()` 继续阻塞。 | [TESTABLE] 关闭 output fd，从 gVisor 发包触发致命错误，验证 Run() 在合理时间内（≤1s）返回 |
| S-OUT-2 | 出向 goroutine 遇到**瞬时写错误**（ENOBUFS / EMSGSIZE / 其他非致命 errno）时，丢弃当前包，log 一行，继续处理下一个包。 | [TESTABLE] mock 一个 Writer：前 N 次返回 ENOBUFS，之后正常；验证后续包仍然写出成功 |
| S-OUT-3 | 瞬时错误发生时，日志包含 `"outbound write transient"` 关键字和具体错误信息。 | [TESTABLE] 检查 log 输出 |
| S-OUT-4 | 致命错误发生时，日志包含 `"outbound write fatal"` 关键字和具体错误信息。 | [TESTABLE] 检查 log 输出 |

### 1.3 isFatalWriteErr 判定表

| 输入 error | 期望返回 |
|-----------|----------|
| `nil` | `false` |
| `syscall.EPIPE` | `true` |
| `syscall.EBADF` | `true` |
| `syscall.ECONNRESET` | `true` |
| `syscall.ENOTCONN` | `true` |
| `io.ErrClosedPipe` | `true` |
| `os.ErrClosed` | `true` |
| `syscall.ENOBUFS` | `false` |
| `syscall.EMSGSIZE` | `false` |
| `fmt.Errorf("wrap: %w", syscall.EPIPE)` | `true`（errors.Is 穿透 wrap） |
| `errors.New("random error")` | `false`（未知错误不视为致命，默认丢包继续） |

### 1.4 Channel 容量

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-CH-1 | `channel.New()` 的 buffer size 不小于 **1024**。256 在高并发下会丢包。 | [TESTABLE] 检查初始化参数 |

### 1.5 VPN 健康检查

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-HEALTH-1 | `Run()` 启动后，每隔 **1 秒** 向 output fd 发送一个 **0 字节** 的 write 探测 VPN 是否存活（与原版 `cb_housekeeping` 行为一致）。 | [TESTABLE] 用 socketpair 的读端检查是否每秒收到 0 字节 datagram |
| S-HEALTH-2 | 如果 0 字节 write 返回 ECONNREFUSED 或 ENOTCONN，判定 VPN 已死亡，`Run()` 返回错误。 | [TESTABLE] 关闭 socketpair 对端后等待，验证 Run() 在 ≤2s 内返回 |
| S-HEALTH-3 | 如果 0 字节 write 返回其他瞬时错误（如 ENOBUFS），忽略，不判定为死亡。 | [TESTABLE] mock Writer 返回 ENOBUFS，验证 Run 继续运行 |
| S-HEALTH-4 | 健康检查日志：VPN 死亡时输出包含 `"vpn health check failed"` 的日志。 | [TESTABLE] 检查 log 输出 |

### 1.6 per-packet 内存优化

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-PERF-1 | 入向读取 buffer（65535 字节）使用 `sync.Pool` 或等价机制复用，避免每包 `make`。注意：拷贝给 gVisor 的 `data` 切片不能复用（生命周期归 gVisor 管），但外层大 buffer 应该复用。 | [TESTABLE] 运行 benchmark，对比优化前后 allocs/op |

> 注：当前实现里外层 `pktBuf` 已经是循环复用的（`make` 在循环外），每包 `make` 的是内层 `data`。内层 `data` 因为所有权转给 gVisor，无法用 pool。所以此条**现状已合理**，仅在 outbound 的 `buf.Flatten()` 侧考虑是否可优化。

---

## 2. socks — SOCKS5 代理服务器（`internal/socks/socks.go`）

### 2.1 协议合规

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-PROTO-1 | 收到客户端第一个字节后，验证 `VER == 0x05`。非 0x05 时回复 `{0x05, 0xFF}`（无可接受方法）并关闭连接，日志记录 `"unsupported SOCKS version"` 和对端地址。 | [TESTABLE] 发送 `{0x04, 0x01, 0x00}` (SOCKS4)，验证收到 `{0x05, 0xFF}` 且连接被关闭 |
| SK-PROTO-2 | 解析 SOCKS request 时，验证 CMD 字段。仅支持 CONNECT (0x01)。BIND (0x02) 和 UDP_ASSOCIATE (0x03) 回复 `REP=0x07`（Command not supported），日志记录命令类型和对端地址。 | [TESTABLE] 发送 CMD=0x03 的请求，验证收到 REP=0x07 |
| SK-PROTO-3 | ATYP=0x04 (IPv6) 回复 `REP=0x08`（Address type not supported），日志记录。不能静默断开。 | [TESTABLE] 发送 ATYP=0x04 的请求，验证收到 REP=0x08 |
| SK-PROTO-4 | 所有 SOCKS 握手阶段的 `conn.Write` 必须检查返回值。写失败时记日志并关闭连接。 | [TESTABLE] 在握手阶段关闭客户端连接，验证 server 不 panic 并有日志 |

### 2.2 超时

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-TIMEOUT-1 | SOCKS 握手阶段（从 Accept 到发出连接成功/失败响应）总超时 **30 秒**。超时后关闭连接，日志记录 `"socks handshake timeout"`。 | [TESTABLE] 连接后不发任何数据，验证 30s 后连接被关闭 |
| SK-TIMEOUT-2 | `DialTCP` 连接远端超时 **15 秒**。超时后向客户端回复 `REP=0x04`（Host unreachable），日志记录。 | [TESTABLE] 拨向一个黑洞地址（如 gVisor 内网段里不存在的 IP），验证 15s 内收到失败响应 |

### 2.3 IPv6 安全

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-IP-1 | `resolve()` 返回的 IP 必须是 IPv4。如果系统 DNS fallback (`net.LookupIP`) 只返回 IPv6 地址，视为解析失败，回复 `REP=0x04`。绝不能将 IPv6 IP 传入 `To4()` 导致 nil panic。 | [TESTABLE] mock resolver 只返回 `::1`，验证不 panic 且客户端收到错误回复 |
| SK-IP-2 | `net.LookupIP` fallback 路径优先选择 IPv4 地址。遍历结果列表，取第一个 `.To4() != nil` 的地址。 | [TESTABLE] mock resolver 返回 `[::1, 1.2.3.4]`，验证选中 `1.2.3.4` |

### 2.4 连接生命周期

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-LIFE-1 | 数据转发阶段（`io.Copy` 双向），必须等**两个方向都结束**后才关闭连接。单方向结束时对另一方向做 half-close（TCP FIN），等待对端也结束。 | [TESTABLE] 客户端发完数据后 close 写端，验证 server→client 方向的剩余数据仍然完整传输 |
| SK-LIFE-2 | 连接建立时日志包含：客户端地址、目标 host、解析后的 IP、端口。 | [TESTABLE] 检查 log 输出格式 |
| SK-LIFE-3 | 连接关闭时日志包含：客户端地址、目标 host、持续时间、传输字节数（双向）。 | [TESTABLE] 检查 log 输出 |

### 2.5 连接数限制

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-LIMIT-1 | 活跃连接数上限 **1024**（可通过参数配置）。达到上限时，新连接仍然 Accept 但立即回复 `REP=0x01`（General SOCKS server failure）并关闭，日志记录 `"max connections reached"`。 | [TESTABLE] 建立 1024 个连接后再建一个，验证第 1025 个收到 REP=0x01 |
| SK-LIMIT-2 | 连接关闭后计数器递减，后续新连接可以正常接入。 | [TESTABLE] 关闭一个连接后建新连接，验证成功 |

### 2.6 统计与可观测性

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-STATS-1 | 维护以下计数器：活跃连接数、历史最大连接数、总连接数、总传输字节数（in/out）、DNS cache 命中数 / 未命中数。 | [TESTABLE] 建立并关闭若干连接后，检查计数器值 |
| SK-STATS-2 | 收到 SIGUSR1 信号时，输出当前统计到日志。格式至少包含：`"connections: active=%d max=%d total=%d dns_cache_hit=%d miss=%d"` | [TESTABLE] 发送 SIGUSR1，检查 log 输出 |

---

## 3. DNS 解析器（`internal/socks/socks.go` DNS 部分）

### 3.1 DNS 域名后缀

| ID | 行为 | 验证方式 |
|----|------|----------|
| DNS-SUFFIX-1 | 支持 `CISCO_DEF_DOMAIN` 环境变量和 `-o` 命令行参数设置默认域名后缀。 | [TESTABLE] 设置 env 后初始化 Server，检查配置 |
| DNS-SUFFIX-2 | 对**不含 `.` 的裸主机名**（如 `intranet`），先查询原始名称，失败后追加后缀再查（如 `intranet.corp.example.com`）。两阶段解析。 | [TESTABLE] mock DNS server：`intranet` 返回 NXDOMAIN，`intranet.corp.example.com` 返回 A 记录；验证最终解析成功 |
| DNS-SUFFIX-3 | 对**包含 `.` 的 FQDN**（如 `www.google.com`），只查原始名称，不追加后缀。 | [TESTABLE] mock DNS server，验证不发送带后缀的查询 |
| DNS-SUFFIX-4 | 无后缀配置时，行为与当前一致（单次查询）。 | [TESTABLE] 不设置 env/flag，验证单次查询 |

### 3.2 DNS Cache 淘汰

| ID | 行为 | 验证方式 |
|----|------|----------|
| DNS-CACHE-1 | cache 容量上限 **512** 条。满时淘汰最早过期的条目（或 LRU）。 | [TESTABLE] 写入 513 条，验证总数 ≤ 512 |
| DNS-CACHE-2 | 后台每 **60 秒** 清理已过期条目，释放内存。 | [TESTABLE] 写入 TTL=1s 的条目，等 60s+，验证条目被删除 |
| DNS-CACHE-3 | TTL 下界 30 秒，上界 1 小时（现有行为保留）。 | [TESTABLE] 分别传入 TTL=1s 和 TTL=2h，验证 clamp |

---

## 4. main — 进程生命周期（`main.go`）

### 4.1 启动

| ID | 行为 | 验证方式 |
|----|------|----------|
| M-START-1 | SOCKS5 server 监听失败时，进程以非零退出码退出，stderr 包含错误原因。不能静默继续。 | [TESTABLE] 先占用端口，再启动 go-ocproxy，验证退出码 ≠ 0 |
| M-START-2 | 启动日志包含：版本号、监听地址、内部 IP、MTU、DNS 服务器列表、DNS 域名后缀（如有）。 | [MANUAL] 检查启动输出 |

### 4.2 信号处理

| ID | 行为 | 验证方式 |
|----|------|----------|
| M-SIG-1 | SIGINT / SIGTERM：优雅关闭。先关闭 SOCKS listener（不再接受新连接），等待活跃连接完成（最多 **5 秒**），关闭 VPN fd，退出。所有 defer 必须执行。 | [TESTABLE] 发 SIGTERM，验证进程退出且 vpnFile 被关闭 |
| M-SIG-2 | SIGHUP：与 SIGINT 相同行为（兼容原版）。 | [TESTABLE] 发 SIGHUP，验证优雅退出 |
| M-SIG-3 | SIGUSR1：输出统计信息到日志（见 SK-STATS-2），不退出。 | [TESTABLE] 发 SIGUSR1 后进程仍在运行 |
| M-SIG-4 | SIGPIPE：忽略。Go runtime 默认处理，但显式确认不能因 SIGPIPE 崩溃。 | [TESTABLE] 关闭 pipe 写端后触发写入，进程不崩 |

### 4.3 命令行参数

| ID | 行为 | 验证方式 |
|----|------|----------|
| M-FLAG-1 | `-D <port>`：SOCKS5 监听端口，默认 1080。 | [TESTABLE] |
| M-FLAG-2 | `-V`：打印版本并退出。 | [TESTABLE] |
| M-FLAG-3 | `-ip <addr>`：覆盖 `INTERNAL_IP4_ADDRESS`。 | [TESTABLE] |
| M-FLAG-4 | `-mtu <bytes>`：覆盖 `INTERNAL_IP4_MTU`，默认 1500。 | [TESTABLE] |
| M-FLAG-5 | `-o <domain>`：DNS 域名后缀，覆盖 `CISCO_DEF_DOMAIN`。 | [TESTABLE] |
| M-FLAG-6 | `-k <seconds>`：TCP keepalive 间隔（秒）。0 表示不启用。默认 0。 | [TESTABLE] |

### 4.4 TCP Keepalive

| ID | 行为 | 验证方式 |
|----|------|----------|
| M-KA-1 | 当 `-k` > 0 时，所有通过 gVisor 拨出的 TCP 连接设置 keepalive，间隔为指定秒数。 | [TESTABLE] 建立连接后检查 gVisor TCP 选项 |
| M-KA-2 | 当 `-k` = 0 或未指定时，不设置 keepalive（gVisor 默认行为）。 | [TESTABLE] |

---

## 5. 日志规范

### 5.1 日志级别约定

go-ocproxy 使用标准 `log` 包。所有日志行以方括号标签开头标识模块：

```
[stack]   — 网络栈 I/O
[socks]   — SOCKS5 协议处理
[dns]     — DNS 解析
[main]    — 进程生命周期
[health]  — VPN 健康检查
```

### 5.2 必须记录的事件

| 事件 | 日志内容 | 来源 |
|------|----------|------|
| 进程启动 | 版本、监听地址、IP、MTU、DNS 服务器 | [main] |
| SOCKS 连接建立 | 客户端地址 → 目标 host (解析 IP):port | [socks] |
| SOCKS 连接关闭 | 客户端地址 → 目标 host，持续时间，字节数 | [socks] |
| SOCKS 握手失败 | 客户端地址、失败原因（版本错误 / 不支持的命令 / 不支持的地址类型 / 超时） | [socks] |
| DNS 解析成功 | 域名 → IP，TTL，来源（cache hit / UDP / TCP fallback） | [dns] |
| DNS 解析失败 | 域名、尝试的服务器、错误原因 | [dns] |
| 出向包写失败（瞬时） | 错误类型、丢弃包计数 | [stack] |
| 出向包写失败（致命） | 错误类型 | [stack] |
| VPN 健康检查失败 | 错误类型 | [health] |
| 连接数达上限 | 当前连接数 | [socks] |
| SIGUSR1 统计 | 连接数、最大连接数、DNS cache 大小 / 命中率 | [main] |
| 优雅关闭开始 | 信号类型 | [main] |
| 优雅关闭完成 | 等待的连接数 | [main] |

### 5.3 不应记录的事件

- 每个正常转发的数据包（太多）
- DNS cache 每次命中（太多，统计数字够用）
- SOCKS auth 成功（正常流程，无需记录）

---

## 6. 测试覆盖矩阵

### 6.1 单元测试（不需要真实 openconnect）

| 测试文件 | 覆盖 |
|----------|------|
| `stack/stack_test.go` | S-IN-*, S-OUT-*, S-CH-1, isFatalWriteErr 判定表 |
| `socks/socks_test.go` | SK-PROTO-*, SK-IP-*, DNS-SUFFIX-*, DNS-CACHE-* |
| `socks/socks_test.go` | buildDNSQuery / parseDNSResponse / skipDNSName 边界 |

### 6.2 集成测试（需要 socketpair 或 mock VPN fd）

| 测试文件 | 覆盖 |
|----------|------|
| `stack/integration_test.go` | S-HEALTH-*, S-OUT-1 主循环通知 |
| `socks/integration_test.go` | SK-TIMEOUT-*, SK-LIMIT-*, SK-LIFE-* |

### 6.3 端到端测试（需要真实 openconnect 或 mock 脚本）

| 测试文件 | 覆盖 |
|----------|------|
| `e2e_test.go` | M-START-*, M-SIG-* |

---

## 附录 A：与原版 C ocproxy 的行为差异记录

以下列出 Go 版本**有意**与原版不同的行为（如有），需在此处注明原因：

| 行为 | 原版 | Go 版本 | 原因 |
|------|------|---------|------|
| 网络栈 | lwIP（C，~80K LOC） | gVisor netstack（Go） | 减少维护成本 |
| 事件模型 | libevent（单线程回调） | goroutine-per-connection | Go 惯用模式 |
| 端口转发 `-L` | 支持 | 不支持 | 当前不需要，SOCKS5 已覆盖所有场景 |
| 远程访问 `-g` | 支持 | 不支持（硬编码 127.0.0.1） | 安全考虑，不暴露到非本机 |
| vpnns 命名空间隔离 | 支持（Linux） | 不支持 | 目标平台 macOS，无 Linux namespace |
| tcpdump `-T` | 支持 | 不支持 | 暂不需要 |

如有新的有意差异，必须更新此表。
