# go-ocproxy 行为规格说明

本文档定义 go-ocproxy 各模块的预期行为，作为实现和测试的唯一参照。
每条规格标注 `[TESTABLE]` 表示可编写自动化测试验证，`[MANUAL]` 表示需人工或集成环境验证。

---

## 1. netstack — 网络栈 I/O（`netstack/netstack.go`）

### 1.1 Inbound：VPN → gVisor

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-IN-1 | 每次 `tunnel.Read()` 必须用 ≥65535 字节的 buffer 一次读取完整 datagram。禁止分多次读（如先读 header 再读 payload）。 | [TESTABLE] 构造 SOCK_DGRAM socketpair，写入完整 IP 包，验证 Read 端一次拿到全部字节 |
| S-IN-2 | 读到的字节数 < 20 时丢弃该包（不够 IPv4 header），不报错，继续读下一个。 | [TESTABLE] 写入 10 字节短包，验证不触发错误，后续正常包仍能处理 |
| S-IN-3 | `tunnel.Read()` 返回 error 时，`Run()` 立即返回该 error。 | [TESTABLE] 关闭 socketpair 写端，验证 Run 返回错误 |
| S-IN-4 | 每个入向包通过 `buffer.MakeWithData` 一次拷贝到 gVisor 所有的存储；不得先 `bytes.Clone` 再二次拷贝。 | [TESTABLE] 连续写入两个不同内容的包，验证内容独立；benchmark 检查分配 |

### 1.2 Outbound：gVisor → VPN

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-OUT-1 | 出向 goroutine 遇到**致命写错误**（EPIPE / EBADF / ECONNRESET / ENOTCONN / io.ErrClosedPipe / os.ErrClosed）时退出，并**通知主循环**使 `Run()` 尽快返回。不能只退出 goroutine 而让 `Run()` 继续阻塞。 | [TESTABLE] 关闭 output fd，从 gVisor 发包触发致命错误，验证 Run() 在合理时间内（≤1s）返回 |
| S-OUT-2 | 出向 goroutine 遇到**瞬时写错误**（ENOBUFS / EMSGSIZE / 其他非致命 errno）时，按指数退避（1ms→32ms 上限）**重试同一个包**最多 `outboundMaxRetries` 次，期间不丢包；重试全部失败才丢这一个包并继续处理下一个。**任何情况下都不能因瞬时错误退出 goroutine 或终止 `Run()`**——上一版直接退出会导致大文件上传后 SOCKS5 服务整体挂掉。 | [TESTABLE] mock Writer 序列 ENOBUFS×N 然后 nil，验证最终成功；持续 ENOBUFS 时验证 goroutine 不退出且 `Run()` 仍在跑 |
| S-OUT-3 | 瞬时错误重试耗尽（即真的丢包）时，按秒聚合日志（每秒至多一行），关键字 `"outbound dropped"`，包含丢包计数和最近一个错误。**每包丢失不打日志**——避免抖动期刷屏。 | [TESTABLE] 检查 log 输出格式与频率 |
| S-OUT-4 | 致命错误发生时，日志包含 `"outbound write fatal"` 关键字和具体错误信息。 | [TESTABLE] 检查 log 输出 |
| S-OUT-5 | 出向 goroutine 必须使用 `net.Conn.Write`（而非 `*os.File.Write`）写 VPN fd。原因：`net.FileConn` dup fd 后会强制把它设为 `O_NONBLOCK`，dup 出的 fd 共享同一 file description，O_NONBLOCK 标志位也共享 → 原 `*os.File` 也变成非阻塞，裸 `Write` 在 buffer 满时直接返回 EAGAIN 而非由 Go runtime poller 自动等可写。`net.Conn.Write` 走 poller 会正确等可写，不会造成"上传卡死"。 | [MANUAL] 大文件（≥ 10MB）SOCKS5 上传不卡 1% |
| S-OUT-6 | transport 建立后通过 `net.UnixConn` / `net.UDPConn` 的 `SetWriteBuffer`、`SetReadBuffer` 将缓冲区请求值调到 1 MiB；不直接操作平台 fd/handle。 | [TESTABLE] mock buffer setter；两平台构建 |

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
| S-HEALTH-1 | macOS 每隔 **1 秒**用 `getpeername` 检查 AF_UNIX datagram peer，不发送探测数据。 | [TESTABLE] socketpair 关闭 peer 后检查返回 |
| S-HEALTH-2 | macOS 收到 ENOTCONN / ECONNRESET / ECONNREFUSED / EBADF 时判定 transport 死亡，`Run()` 返回错误。 | [TESTABLE] 关闭 socketpair 对端后等待，验证 Run() 在 ≤2s 内返回 |
| S-HEALTH-3 | Windows connected UDP 不伪造 socket 存活检测；helper 与 go-ocproxy 必须互相监督进程生命周期。 | [TESTABLE] Windows UDP Run 测试；消费方 helper 集成测试 |
| S-HEALTH-4 | 健康检查日志：VPN 死亡时输出包含 `"vpn health check failed"` 的日志。 | [TESTABLE] 检查 log 输出 |

### 1.6 per-packet 内存优化

| ID | 行为 | 验证方式 |
|----|------|----------|
| S-PERF-1 | 入向读取 buffer（65535 字节）使用 `sync.Pool` 或等价机制复用，避免每包 `make`。注意：拷贝给 gVisor 的 `data` 切片不能复用（生命周期归 gVisor 管），但外层大 buffer 应该复用。 | [TESTABLE] 运行 benchmark，对比优化前后 allocs/op |

> 注：当前实现里外层 `pktBuf` 已经是循环复用的（`make` 在循环外），每包 `make` 的是内层 `data`。内层 `data` 因为所有权转给 gVisor，无法用 pool。所以此条**现状已合理**，仅在 outbound 的 `buf.Flatten()` 侧考虑是否可优化。

---

## 2. proxy — SOCKS5 + HTTP 代理服务器（`proxy/socks5.go`、`proxy/http.go`）

监听端口同时承载 SOCKS5 和 HTTP 代理，靠首字节嗅探分流（见 SK-SNIFF-1）。

### 2.1 协议合规

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-SNIFF-1 | Accept 后用 `bufio.Reader.Peek(1)` 读首字节：在 `'A'..'Z'` 范围内则交给 HTTP handler；其余（含 `0x05`）交给 SOCKS5 handler。Peek 失败按 SOCKS 同样的连接关闭路径处理。 | [TESTABLE] 发 `GET / HTTP/1.1\r\n...` 验证返回 `HTTP/1.1` 状态行；发 `{0x05, ...}` 走原 SOCKS 流程 |
| SK-PROTO-1 | 进入 SOCKS5 handler 后，验证 `VER == 0x05`。非 0x05 时回复 `{0x05, 0xFF}`（无可接受方法）并关闭连接，日志记录 `"unsupported SOCKS version"` 和对端地址。 | [TESTABLE] 发送 `{0x04, 0x01, 0x00}`，验证收到 `{0x05, 0xFF}` 且连接被关闭 |
| SK-PROTO-2 | 解析 SOCKS request 时，验证 CMD 字段。仅支持 CONNECT (0x01)。BIND (0x02) 和 UDP_ASSOCIATE (0x03) 回复 `REP=0x07`（Command not supported），日志记录命令类型和对端地址。 | [TESTABLE] 发送 CMD=0x03 的请求，验证收到 REP=0x07 |
| SK-PROTO-3 | ATYP=0x04 (IPv6) 读取 16 字节 IPv6 地址，正常处理连接请求。 | [TESTABLE] 发送 ATYP=0x04 的请求，验证不返回 REP=0x08 |
| SK-PROTO-4 | 所有 SOCKS 握手阶段的 `conn.Write` 必须检查返回值。写失败时记日志并关闭连接。 | [TESTABLE] 在握手阶段关闭客户端连接，验证 server 不 panic 并有日志 |

### 2.2 超时

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-TIMEOUT-1 | SOCKS 握手阶段（从 Accept 到发出连接成功/失败响应）总超时 **30 秒**。超时后关闭连接，日志记录 `"socks handshake timeout"`。 | [TESTABLE] 连接后不发任何数据，验证 30s 后连接被关闭 |
| SK-TIMEOUT-2 | `DialTCP` 连接远端超时 **15 秒**。超时后向客户端回复 `REP=0x04`（Host unreachable），日志记录。 | [TESTABLE] 拨向一个黑洞地址（如 gVisor 内网段里不存在的 IP），验证 15s 内收到失败响应 |

### 2.3 IPv6 双栈

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-IP-1 | `resolve()` 优先返回 IPv4（A 记录）。当栈有 IPv6 且 A 查询无结果时，回退到 AAAA 记录。不配置 IPv6 时，只查 A 记录。 | [TESTABLE] 验证优先返回 IPv4；栈有 IPv6 时能返回 AAAA 结果 |
| SK-IP-2 | 系统 resolver fallback 必须调用可取消的 `net.DefaultResolver.LookupNetIP(ctx, ...)` 并优先选 IPv4；无 IPv4 且栈有 IPv6 时选 IPv6。 | [TESTABLE] 取消 context，验证解析及时停止；验证 IPv4 优先 |

### 2.4 连接生命周期

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-LIFE-1 | 数据转发阶段（`io.Copy` 双向），必须等**两个方向都结束**后才关闭连接。单方向结束时对另一方向做 half-close（TCP FIN），等待对端也结束。 | [TESTABLE] 客户端发完数据后 close 写端，验证 server→client 方向的剩余数据仍然完整传输 |
| SK-LIFE-2 | 连接建立时日志包含：客户端地址、目标 host、解析后的 IP、端口。 | [TESTABLE] 检查 log 输出格式 |
| SK-LIFE-3 | 连接关闭时日志包含：客户端地址、目标 host、持续时间、传输字节数（双向）。 | [TESTABLE] 检查 log 输出 |

### 2.5 连接数限制

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-LIMIT-1 | 活跃连接数上限 **1024**。达到上限时，在协议嗅探前立即关闭新连接并记录 `"max connections reached"`；此时协议尚未知，不能伪造 SOCKS5 回复。 | [TESTABLE] 填满限流槽后建立新连接，验证立即关闭 |
| SK-LIMIT-2 | 连接关闭后计数器递减，后续新连接可以正常接入。 | [TESTABLE] 关闭一个连接后建新连接，验证成功 |

### 2.6 统计与可观测性

| ID | 行为 | 验证方式 |
|----|------|----------|
| SK-STATS-1 | 维护以下计数器：活跃连接数、历史最大连接数、总连接数、总传输字节数（in/out）、DNS cache 命中数 / 未命中数。 | [TESTABLE] 建立并关闭若干连接后，检查计数器值 |
| SK-STATS-2 | 收到 SIGUSR1 信号时，输出当前统计到日志。格式至少包含：`"connections: active=%d max=%d total=%d dns_cache_hit=%d miss=%d"` | [TESTABLE] 发送 SIGUSR1，检查 log 输出 |

### 2.7 HTTP 代理协议（`proxy/http.go`）

HTTP handler 复用 SOCKS 的连接生命周期、连接数限制、DNS 解析与统计逻辑。

| ID | 行为 | 验证方式 |
|----|------|----------|
| HT-CONNECT-1 | `CONNECT host:port HTTP/1.1` 请求：解析出 host/port，缺端口默认 `443`；通过 NetStack 拨号成功后回复 `HTTP/1.1 200 Connection Established\r\n\r\n`，随后清除 deadline 进入双向拷贝（与 SOCKS 共用 `bidirectionalCopy`）。 | [TESTABLE] 集成测试发 CONNECT，验证 200 响应与隧道字节透传 |
| HT-CONNECT-2 | IPv4 和 IPv6 字面量地址均可作为 CONNECT 目标；拨号失败时回 `502 Bad Gateway`。 | [TESTABLE] `CONNECT [::1]:443` → 尝试拨号，失败时 502 |
| HT-CONNECT-3 | 拨号失败（NetStack 错误、DNS 解析失败）回 `502 Bad Gateway`。 | [TESTABLE] 拨向不可达地址 → 502 |
| HT-FORWARD-1 | 普通 HTTP 请求（绝对 URI，如 `GET http://host/path HTTP/1.1`）：解析 `req.URL.Host` 拨号上游，转发后写回响应。`req.URL.Host` 为空（相对 URI）时回 `400 Bad Request`。 | [TESTABLE] 发相对 URI → 400；绝对 URI 集成测试 |
| HT-FORWARD-2 | 转发前剥离 hop-by-hop 头：`Connection`、`Keep-Alive`、`Proxy-Authenticate`、`Proxy-Authorization`、`Proxy-Connection`、`Te`、`Trailer`、`Transfer-Encoding`、`Upgrade`，以及 `Connection` header 中列出的所有自定义头。响应头同样剥离。 | [TESTABLE] 单元测试 `removeHopByHopHeaders` |
| HT-FORWARD-3 | 转发请求强制 `Connection: close`，响应也强制 `Connection: close`，每次请求新建上游连接。不实现客户端侧 keep-alive 复用。 | [TESTABLE] 检查上游收到的请求头与回写客户端的响应头 |
| HT-FORWARD-4 | 缺端口时按 scheme 推断默认端口：HTTP 转发 `80`，CONNECT `443`。端口非数字字符串（如 `:abc`）回 `400`。 | [TESTABLE] 单元测试 `splitHostPortDefault`；集成测试 `CONNECT host:abc` → 400 |
| HT-ERR-1 | `http.ReadRequest` 解析失败时，回 `400 Bad Request` 后关闭连接，不静默断开（便于浏览器显示错误）。 | [TESTABLE] 发畸形请求行 → 400 |
| HT-AUTH-1 | 不实现 HTTP 代理认证（与 SOCKS5 一致的无认证策略）。`Proxy-Authorization` 头被无条件剥离。 | [MANUAL] |
| HT-IPV6-1 | 支持向 IPv6 目标拨号（当栈有 IPv6 时），行为与 SK-IP-1 一致。 | 同 HT-CONNECT-2 |

---

## 3. DNS 解析器（`proxy/dns.go`）

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
| DNS-CACHE-4 | 同一名称并发 cache miss 共享一次在途解析；不同名称互不阻塞。缓存命中/未命中仍按调用次数统计。TTL=0 只合并在途请求，不额外缓存。 | [TESTABLE] 并发解析计数；不同名称；TTL=0 |
| DNS-CANCEL-1 | 每个解析调用可独立取消，不能中止其他等待者；最后一个等待者退出后取消共享查询。共享查询最长 15 秒，取消或超时不写入负缓存。 | [TESTABLE] 单个取消、全部取消、独立重试和超时 |

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
| M-FLAG-1 | `-D <port>`：SOCKS5/HTTP 代理监听端口（同端口嗅探），默认 1080。 | [TESTABLE] |
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
[netstack] — 网络栈 I/O
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
| 出向包写失败（瞬时） | 错误类型、丢弃包计数 | [netstack] |
| 出向包写失败（致命） | 错误类型 | [netstack] |
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

### 6.0 Windows 平台适配

| ID | 行为 | 验证方式 |
|----|------|----------|
| WIN-FD-1 | Windows transport 使用 `net.UDPConn` 的跨平台方法，不直接把 socket handle 当 Unix fd 调用 `syscall`。 | [TESTABLE] Windows native test + build |
| WIN-FD-2 | `VPNFD` 缺失但设置 `VPN_UDP_PEER=127.0.0.1:<port>` 时，进程必须建立 connected UDP transport，把 `VPN_UDP_TOKEN` 原样作为首个 datagram 发送，并继续按“一 datagram 一 IP 包”语义运行。该通道只接受 loopback + 非零端口，可供 Windows libopenconnect `openconnect_setup_tun_fd(HANDLE)` 的外部 helper 接入；不得回退到会破坏包边界的 stdin/stdout 字节流。 | [TESTABLE] 本机 UDP listener 校验 token、双向 datagram 边界和非 loopback 拒绝行为 |
| WIN-FD-3 | 使用 `VPN_UDP_PEER` 时必须同时设置随机 `VPN_UDP_TOKEN`，供 helper 精确校验并防止其他本机进程抢先注入。token 最长 128 字节；缺失或超限必须拒绝启动。 | [TESTABLE] 覆盖缺失、有效和超长 token |
| WIN-SIG-1 | Windows 上 Ctrl+C / Interrupt / SIGTERM 触发优雅关闭；Windows 没有 SIGUSR1，因此不提供信号触发的 stats dump。 | [MANUAL] 启动后发送控制台中断，验证进程退出 |
| WIN-BUILD-1 | `GOOS=windows GOARCH=amd64 go build` 必须成功，产出可由外部 libopenconnect helper 通过 `VPN_UDP_PEER` 启动的 PE32+ 可执行文件。 | [TESTABLE] Windows CI/native build |
| WIN-LIFE-1 | connected UDP 的 `getpeername` 只能验证 peer 已配置，不能可靠判断 helper 进程仍存活；Windows helper 必须把 go-ocproxy 纳入自身生命周期管理，helper 或父进程退出时同步终止 go-ocproxy。 | [MANUAL] 终止 helper/父进程，确认 go-ocproxy 被回收 |

### 6.1 单元测试（不需要真实 openconnect）

| 测试文件 | 覆盖 |
|----------|------|
| `netstack/netstack_darwin_test.go` | S-IN-*, S-OUT-*, S-CH-1, isFatalWriteErr, writeOutboundWithRetry |
| `netstack/monitor_windows_test.go` | Windows UDP transport 与 Run 生命周期 |
| `transport/open_windows_test.go` | loopback/token 校验与双向 datagram |
| `proxy/proxy_test.go` | SOCKS5、HTTP、DNS、cache、限流与生命周期 |

### 6.2 平台集成测试

平台集成测试与单元测试放在同一包中，通过 `_darwin_test.go` / `_windows_test.go`
文件名选择目标系统；CI 在 macOS 与 Windows 原生执行测试，并交叉构建 macOS arm64 / Windows amd64 发布目标。真实 OpenConnect
链路仍需发布前手工 smoke test。

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
| 出站写阻塞策略 | C `write()` + `select`/`poll` 显式等可写 | `net.Conn.Write` 走 Go runtime poller，ENOBUFS 由 `writeOutboundWithRetry` 退避重试 | Go 语言惯用法；同时绕开 `net.FileConn` 把 dup fd 设 `O_NONBLOCK` 影响共享 file description 的隐性问题（详见 `AGENTS.md` 的"非阻塞 fd 陷阱"） |
| Windows 统计信号 | N/A | 不支持 SIGUSR1；保留正常日志和退出控制信号 | Windows 控制台没有 POSIX SIGUSR1 |

如有新的有意差异，必须更新此表。
