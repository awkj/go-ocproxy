# go-ocproxy

English | [简体中文](README_zh.md)

**A gVisor-based user-space network proxy that turns an IP packet channel into SOCKS5 / HTTP access.**

`go-ocproxy` bridges application proxy protocols and an IP network stack in Go.
Applications make TCP / UDP requests through the local proxy; gVisor netstack handles
the network protocols and exchanges IP packets over a bidirectional channel supplied
by an external program.

**SOCKS5, HTTP forwarding, and HTTPS CONNECT share one port: `127.0.0.1:1080` by default.**
The proxy needs no system TUN interface and does not change system routes or DNS.
An external program establishes and maintains the packet channel.

```text
Applications ── SOCKS5 / HTTP ── go-ocproxy (gVisor netstack) ── IP packet channel ── Target network
```

## What you can do with it

- Expose an existing VPN packet channel as a local proxy for browsers, command-line tools, and other applications.
- Reuse a user-space TCP/IP stack in your own networking tools, with proxy requests handled by a separate process.
- Provide SOCKS5 / HTTP access to an external program capable of sending and receiving IP packets.

OpenConnect's `--script-tun` provides one ready-made integration. Other programs can
adapt to the existing packet transport and configuration conventions: an inherited
Unix datagram socket on Linux / macOS, or loopback UDP on Windows. Each datagram must
carry one complete IP packet. See the integration details below.

## Features

| Capability | Details |
| --- | --- |
| One proxy port | SOCKS5, HTTP forwarding, and HTTPS CONNECT with automatic protocol detection |
| SOCKS5 TCP / UDP | CONNECT and UDP ASSOCIATE; UDP requires application support; SOCKS5 fragment reassembly is unsupported |
| DNS resolution | Queries configured DNS servers over the packet channel; domain suffixes, caching, and DNS-over-TCP fallback |
| IPv4 / optional IPv6 | IPv4 by default; dual stack when an IPv6 address is configured |
| User-space networking | Built on gVisor netstack; go-ocproxy builds into a single binary |

The proxy listens only on IPv4 loopback (`127.0.0.1`). Proxy authentication and a
configurable remote listening address are not implemented.

## Platforms

| Platform | Release build target | VPN transport |
| --- | --- | --- |
| Linux | amd64 | Inherited Unix datagram socket (`VPNFD`) |
| macOS | arm64 | Inherited Unix datagram socket (`VPNFD`) |
| Windows | amd64 | Connected loopback UDP (`VPN_UDP_PEER`) |

## Get the binary

Download a published platform archive from [Releases](https://github.com/awkj/go-ocproxy/releases),
or build from source.

See [go.mod](go.mod) for the required Go version. From the repository root:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o go-ocproxy .
```

## Connect a packet channel

### Linux / macOS: inherited Unix socket

The parent program must create a connected, bidirectional `AF_UNIX/SOCK_DGRAM` channel,
pass one file descriptor to the child process, and set `VPNFD` to its descriptor number.
Each datagram carries one complete IP packet. The parent connects the other end to the
target network and supplies address, MTU, and DNS configuration.

Setting environment variables or starting go-ocproxy alone does not establish a packet channel.

#### Example: OpenConnect

Install OpenConnect, then run this from the directory containing `go-ocproxy`,
replacing the gateway address:

```bash
openconnect \
  --script-tun \
  --script './go-ocproxy -D 1080' \
  vpn.example.com
```

Complete authentication when prompted and leave the process running. `--script-tun`
passes VPN packets directly to go-ocproxy, which reads the assigned addresses, MTU,
and DNS servers and starts the local proxy.

### Windows: loopback UDP

An external program must provide an IPv4 loopback UDP endpoint to exchange IP packets
with go-ocproxy. When starting go-ocproxy, it supplies address, MTU, and DNS configuration,
along with these environment variables:

| Variable | Requirement |
| --- | --- |
| `VPN_UDP_PEER` | The external program's IPv4 loopback UDP address, such as `127.0.0.1:12345`, with a nonzero port |
| `VPN_UDP_TOKEN` | A random, nonempty token generated for each session, at most 128 bytes |

go-ocproxy sends the exact token as its first UDP datagram. The external program must validate it
before exchanging VPN packets. Each subsequent datagram carries one complete IP packet.
The external program must also supervise the child and terminate go-ocproxy when the
channel closes or the parent exits.

For example, a libopenconnect helper can establish a VPN and attach it through this
channel. Such a helper is not included here; the Windows OpenConnect CLI does not
expose `--script-tun`.

## Use the proxy

Once the external program has connected the packet channel and started go-ocproxy,
run these in another terminal. Replace the example address with a service reachable
through your channel:

```bash
# SOCKS5: let the proxy resolve the target hostname
curl --proxy socks5h://127.0.0.1:1080 https://service.example.com

# HTTP proxy: HTTPS uses a CONNECT tunnel
curl --proxy http://127.0.0.1:1080 https://service.example.com
```

Use `127.0.0.1:1080` for HTTP, HTTPS, and SOCKS5 proxy settings in your browser or
application. Requests sent to this proxy reach their destinations through the packet
channel. Choose which applications or domains use the proxy in application settings,
a PAC file, or a parent tool.

For hostnames over SOCKS5, enable proxy-side DNS resolution; use `socks5h://` in
command-line tools. Without configured DNS servers, go-ocproxy uses the system resolver.

## Configuration

The parent supplies network configuration through environment variables. Some settings
can also be provided as command-line options. OpenConnect supplies these environment
variables when used as the parent.

| Option | Purpose | Default / source |
| --- | --- | --- |
| `-D <port>` | SOCKS5 / HTTP listening port | `1080` |
| `-ip <address>` | Network stack IPv4 address | `INTERNAL_IP4_ADDRESS`, required |
| `-ip6 <address>` | Network stack IPv6 address | `INTERNAL_IP6_ADDRESS`, optional |
| `-mtu <bytes>` | MTU when the environment variable is absent | `1500`; `INTERNAL_IP4_MTU` takes precedence |
| `-o <domain>` | Suffix tried after resolving a bare hostname fails | `CISCO_DEF_DOMAIN` |
| `-k <seconds>` | TCP keepalive interval | `0`, disabled |
| `-V` | Print version and exit | — |

DNS servers come from `INTERNAL_IP4_DNS` and `INTERNAL_IP6_DNS`, with multiple addresses
separated by whitespace. On Linux / macOS, the parent must also pass a valid inherited
`VPNFD`; both address configuration and a packet channel are required.

## Project and development

This is a Go rewrite of [ocproxy](https://github.com/cernekee/ocproxy), using gVisor
netstack for user-space network protocol processing and retaining the OpenConnect
integration conventions.

- [SPEC.md](SPEC.md): behavior contracts, differences from the original, and test matrix.
- [AGENTS.md](AGENTS.md): architecture, maintenance conventions, and implementation notes.
- [docs/CHANGELOG.md](docs/CHANGELOG.md): version history.

## License

Licensed under the [MIT License](LICENSE). Commercial use, modification, and
redistribution are permitted with the copyright and permission notices retained.
Third-party dependencies remain subject to their own licenses, including gVisor's Apache-2.0 license.
