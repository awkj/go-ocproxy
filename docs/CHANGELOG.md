# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/) 风格，版本号采用 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Fixed
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
- 启动时显式调大 VPN fd 的 `SO_SNDBUF` / `SO_RCVBUF` 至 1 MiB（macOS 默认 AF_UNIX
  SOCK_DGRAM 仅约 8 KiB），降低 ENOBUFS 触发概率。
- `stack/stack_test.go` 新增 7 个测试覆盖 `writeOutboundWithRetry` 的所有分支
  （W-RETRY-1..7）：成功、瞬时错误重试后成功、重试耗尽、致命错误立即退出、
  context 取消、SetDeadline 触发、`maxRetries=0` 边界。
- `SPEC.md` 新增 S-OUT-5 / S-OUT-6 行为规格；S-OUT-2 / S-OUT-3 调整以反映
  退避重试 + 按秒聚合日志的新语义。
- 新增 `CLAUDE.md`，给 AI 开发助手 / 长期维护者的项目背景、架构和坑位文档。

### Changed
- 出向 goroutine 不再使用裸 `*os.File.Write`，统一通过 `net.Conn.Write` 写 VPN fd。
- input/output 不再各自 `net.FileConn` dup 一次，复用同一个 `vpnConn`；`SetDeadline`
  同时打断阻塞的 Read 和 Write。
- 瞬时错误日志从"每包一行"改为"每秒至多一行"，减少抖动期日志噪音。

### Internal
- `outboundMaxRetries` / `outboundInitialDelay` / `outboundMaxDelay` 提为包级
  变量，便于测试覆盖时调零绕开真实退避。

## v1.1.0

- Go-gVisor rewrite 首个稳定版本。
- 详见 git log（`62017dd` 修改包名 / `8bdafc5` PacketBuffer 引用泄漏 + DNS-over-TCP
  + 多项健壮性改进 / `8045b45` 重构包结构并添加测试和规格文档）。
