# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/) 风格，版本号采用 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- 更新全部 Go 依赖至当前版本，gVisor 使用 `go` 分支；编译基线升级为 Go 1.27.1。

### Fixed
- 同一域名的并发 DNS cache miss 合并为一次在途查询；调用方独立取消，最后一个
  等待者离开后中止查询。DNS UDP/TCP I/O 响应 context 取消，取消与超时不再污染负缓存。
- Windows 新增通用 `VPN_UDP_PEER` 数据报 transport，供外部 libopenconnect helper
  通过 `openconnect_setup_tun_fd(HANDLE)` 接入，绕开上游 Windows CLI 不支持的
  `--script-tun`；必需的随机 `VPN_UDP_TOKEN` 用于防止本机进程抢先注入握手。
- Windows transport 直接使用 `net.UDPConn` 的跨平台 API，不再维护易错的 handle/fd
  syscall 包装；Windows amd64 上可原生测试和构建。
- netstack 或 proxy server 意外退出现在会传回 `main` 并产生非零进程退出码；不再只记
  日志后继续运行半活进程。系统 DNS fallback 改用支持 context 取消的 `LookupNetIP`。
- **大文件 SOCKS5 上传卡死/连接挂掉**（影响 ≥ ~10 MB 的文件上传场景）。根因是
  `net.FileConn` 会把 dup 出的 fd 强制设为 `O_NONBLOCK`，由于 dup 的 fd 共享同一
  file description，原 `*os.File` 也变成非阻塞，出向使用裸 `*os.File.Write` 在
  socket buffer 满时直接返回 `EAGAIN`，旧代码误把它当 transient 错误**静默丢包**，
  导致 gVisor TCP 重传陷入死循环。修复后出向改走 `net.Conn.Write`，由 Go runtime
  poller 自动等待 fd 可写。
- **macOS `ENOBUFS` 导致 SOCKS5 服务整体退出**（首次修复后引入的副作用）。macOS
  AF_UNIX SOCK_DGRAM 在高吞吐时会因系统 mbuf 池暂时耗尽返回 `ENOBUFS`，Go runtime
  poller 不会自动重试这种错误。新增 `writeOutboundWithRetry` 对瞬时错误做指数
  退避重试（1ms→32ms 上限，最多 10 次合计约 191ms），重试耗尽才丢这一个包，**任何
  情况下都不再因瞬时错误退出 goroutine**。

### Added
- **IPv6 双栈支持**：当 openconnect 通过 `INTERNAL_IP6_ADDRESS` 传入 IPv6 地址时，
  go-ocproxy 可以转发 IPv6 流量。SOCKS5 ATYP=0x04 (IPv6) 不再被拒绝，DNS 解析在
  A 记录无结果时回退到 AAAA 记录。IPv6 完全可选——不配置时行为不变。新增 `-ip6`
  CLI 参数和 `INTERNAL_IP6_DNS` 环境变量支持。
- 启动时通过 `net.UnixConn` / `net.UDPConn` portable setter 请求把 socket buffer 调到
  1 MiB（macOS 默认 AF_UNIX SOCK_DGRAM 仅约 8 KiB），降低 ENOBUFS 触发概率。
- `netstack/netstack_darwin_test.go` 覆盖 `writeOutboundWithRetry` 的所有分支
  （W-RETRY-1..7）：成功、瞬时错误重试后成功、重试耗尽、致命错误立即退出、
  context 取消、SetDeadline 触发、`maxRetries=0` 边界。
- `SPEC.md` 新增 S-OUT-5 / S-OUT-6 行为规格；S-OUT-2 / S-OUT-3 调整以反映
  退避重试 + 按秒聚合日志的新语义。
- 新增 `AGENTS.md`，给 AI 开发助手 / 长期维护者的项目背景、架构和坑位文档。

### Changed
- 双向转发字节统计使用独立局部计数器，并通过 `WaitGroup.Wait` 同步结果，去掉不必要
  的原子操作；并发安全由 race 回归测试验证。
- 出向 goroutine 不再使用裸 `*os.File.Write`，统一通过 `net.Conn.Write` 写 VPN fd。
- input/output 不再各自 `net.FileConn` dup 一次，复用同一个 `vpnConn`；`SetDeadline`
  同时打断阻塞的 Read 和 Write。
- 瞬时错误日志从"每包一行"改为"每秒至多一行"，减少抖动期日志噪音。
- TCP 默认拥塞控制改用 gVisor CUBIC；入站包移除 `bytes.Clone` + `MakeWithData` 的双重
  拷贝；源码按 `transport`、`netstack`、`proxy` 划分。
- gVisor `go` 分支从 `38fac1bddd3c` 升级到 `441f7aafaefa`，`x/net` 升级到
  `v0.58.0`，`x/sys` 升级到 `v0.47.0`；构建环境改为始终跟随最新稳定版 Go（当前 1.26.5）。
- GoReleaser 改为构建完整 package（而非仅 `main.go`），发布范围收敛为 macOS
  arm64 / Windows amd64，并从 release tag 注入版本号。

### Internal
- `outboundMaxRetries` / `outboundInitialDelay` / `outboundMaxDelay` 提为包级
  变量，便于测试覆盖时调零绕开真实退避。

## v1.1.0

- Go-gVisor rewrite 首个稳定版本。
- 详见 git log（`62017dd` 修改包名 / `8bdafc5` PacketBuffer 引用泄漏 + DNS-over-TCP
  + 多项健壮性改进 / `8045b45` 重构包结构并添加测试和规格文档）。
