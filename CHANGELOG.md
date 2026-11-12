# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-11-12

### Added
- **Interactive Terminal TUI (Bubble Tea & Lip Gloss)**:
  - Live animated terminal HUD with pastel pop theme (`#FF8C42` Fox Orange brand, Cyan TLS, Peach HTTP, Lavender DNS, Mint Green metrics, and Rose threats).
  - Split flow inspector drawer (60/40 horizontal split on `[Enter]`) showing TLS SNI, TCP 3WHS latency, and L7 metadata.
  - Threat radar view (`Tab 2` / `[2]`) with filtered real-time MITRE security detections.
  - Traffic analytics view (`Tab 3` / `[3]` / `g`) with 30s rolling throughput sparkline and protocol distribution bars.
  - Smooth viewport scrolling with keyboard (`↑`/`↓`, `k`/`j`, `PgUp`/`PgDn`, `Home`/`End`) and mouse wheel.
  - Non-blocking ring buffer event bridge decoupling 30 FPS UI redraws from the engine's zero-alloc packet ingestion.
  - Headless fallback: `-headless` flag and automatic TTY detection for clean headless execution in CI/CD and scripts.
- **Modern Compact Run Summary**:
  - Replaced legacy raw ASCII tables with a compact, rounded pastel-pop summary card that tightly hugs session telemetry with zero empty space.
- **Engine Live Telemetry Snapshot**:
  - Added real-time active flow polling (`engine.ActiveFlows`) directly from flow table shards for instantaneous packet visualization.

## [0.1.3] - 2026-11-11

### Fixed
- **Zero False Positives Across Modern Dev Stacks**:
  - Whitelisted standard cloud and infrastructure TLS ports (`6443` K8s API, `9443` K8s admission webhooks, `5432` Postgres TLS, `6380` Redis TLS) alongside `443` and `8443` in `SUSPICIOUS_HIGH_PORT_TLS` while preserving high-confidence detection of Metasploit, Cobalt Strike, and raw TCP shells on non-standard ports.
  - Whitelisted local multicast discovery ports `5353` (Apple mDNS, RFC 6762) and `5355` (Windows LLMNR, RFC 4795) from `ANOMALOUS_DNS_PORT`.
  - Added 1-cycle UDP 443 QUIC fixed-bit classification path, bypassing DNS dissection on high-entropy QUIC traffic to prevent false `DNS_TUNNELING_EXFILTRATION` alarms.
  - Verified across 250+ developer, cloud, registry, and CDN targets with 0 false positives.

### Performance & Engine Trims
- **Protocol Dispatching**: Eliminated redundant HTTP prefix scanning in the protocol dispatcher, delegating directly to the zero-allocation HTTP dissector for reduced CPU cycles.
- **Link Layer Decapsulation**: Unified Ethernet and default fallback decapsulation paths into a single execution branch.
- **Flow Engine Cleanups**: Deduplicated TCP flag constants by aliasing `capture.Flag*` and removed dead flow sweep counter writes.
- **Offline PCAP Replay**: Bypassed redundant console alert sink wrapper during offline PCAP replay runs.

## [0.1.2] - 2026-10-21

### Fixed
- **NPX On-Demand Binary Hydration**: Resolved missing binary error during ad-hoc `npx foxdpi` executions by having `bin/foxdpi.js` automatically verify and fetch the compressed native binary on-demand if absent.

## [0.1.1] - 2026-10-21

### Added

#### Native Live Packet Capture
- **Out-of-the-Box Live Capture**: Single command (`foxdpi -i capture`) for live packet capture without third-party drivers (no Npcap, WinPcap, or Wireshark installations required).
- **Intelligent Interface Auto-Detection**: Automatically detects, prioritizes, and binds to active internet-facing network adapters (Wi-Fi/WLAN first, primary Ethernet fallback).
- **Windows Winsock2 Raw Socket Tap**: Pure-Go raw socket tap utilizing `SIO_RCVALL` and native `ws2_32.dll` `recv` via `syscall.SyscallN` for line-rate Layer 3 datagrams.
- **Linux AF_PACKET Source**: Native POSIX `AF_PACKET` raw socket capture delivering Layer 2 Ethernet frames at line-rate.
- **macOS BPF Tap**: Native Berkeley Packet Filter (`/dev/bpf*`) descriptor binding with `BIOCIMMEDIATE` packet delivery.
- **Layer 3 Raw IPv4 Decapsulation**: Zero-allocation decapsulation for raw IPv4 wire frames (`layers.LinkTypeRaw`), bypassing Ethernet framing.

#### Threat Alerting & CLI Operations
- **Real-Time Console Threat Alerting**: Real-time formatted threat alert streaming directly to `stderr` (`ConsoleAlertSink`) concurrent with asynchronous JSON Lines logging.
- **Graceful Terminal Session Summary**: Tabular run summary displayed upon `Ctrl+C` with non-blocking socket termination.
- **Version Flag**: Added `-version` flag to print version information and exit.

### Fixed
- **Windows Raw Socket Packet Reception**: Replaced unsupported `syscall.Recvfrom` stub with `ws2_32.dll` `recv` using `syscall.SyscallN`, fixing `recvfrom: not supported by windows`.
- **Data Link Type Formatting**: Corrected data link presentation from `UnknownLinkType` to `Raw IPv4`.
- **Signal Responsiveness**: Added socket release listener unblocking blocking socket reads immediately on `Ctrl+C`.
- **Privilege Error Handling**: Gracefully intercepts `WSAEACCES` / error 10013 to provide actionable Administrator elevation instructions.

## [0.1.0] - 2026-10-20

### Added

#### Protocol Inspection
- **Passive TLS Dissection**: Extracts SNI hostname, TLS version (1.0–1.3), and flags direct-IP HTTPS handshakes lacking SNI without terminating TLS or installing root certificates.
- **HTTP/1.1 Dissection**: Extracts request methods, target URI paths, User-Agent, and Host headers with RFC 3986 bracketed IPv6 support (`[2001:db8::1]`).
- **DNS Dissection**: Parses standard queries, responses, and QNAMEs with RFC 1035 compression pointer loop protection.
- **String Interning**: Sharded 16-partition `StringInterner` caches repeated domains, hostnames, and paths with zero heap allocations.

#### Threat Detection & Security Alerting
- **High-Port TLS C2 Detection**: Flags encrypted C2 reverse shells and beacons on non-standard ports (e.g., 4444, 1337) with a 1-cycle fast path on ports 443/8443.
- **Protocol Padding Evasion Defense**: Bounded 64-byte sliding scan detects TLS and HTTP payloads obscured behind junk prefix noise (MITRE T1001.003).
- **HTTP Request Smuggling Defense**: Enforces RFC 7230 first-host-wins and alerts on duplicate `Host` headers (`HTTP_DUPLICATE_HOST` / CWE-444).
- **DNS Tunneling Exfiltration Detection**: LUT-accelerated Shannon entropy engine with 2ns fast gate to detect high-entropy encoded exfiltration on port 53 (MITRE T1071.004).
- **Port Spoofing Detection**: Alerts on plaintext HTTP on port 443 and encrypted TLS on port 80.

#### Transport & Flow Lifecycle
- **Canonical 5-Tuple Tracking**: 64-shard concurrent flow table with bidirectional canonical sorting (Low/High IP/Port).
- **Rapid Port Reuse Epochs**: Cleanses connection state upon receiving a new `SYN` during teardown to prevent inspection bypass.
- **Monotonic Timestamp Bounds**: Enforces `FirstSeen <= LastSeen` to eliminate negative connection durations from packet capture clock jitter.
- **Center-Out Stream Reassembly**: Bidirectional 8 KB buffer (4 KB Headroom / 4 KB Tailroom) handles reverse arrivals and mid-stream loss without memory shifting.
- **32-Bit Sequence Rollover**: Modular sequence arithmetic handles sequence numbers wrapping past 2^32-1.

#### Telemetry & Operations
- **Asynchronous Telemetry Sinks**: Streams `flows.jsonl` and `alerts.jsonl` over non-blocking channels with zero-reflection JSON encoding.
- **Automatic Rotation & Compression**: Rotates logs at configurable size thresholds with background gzip compression.
- **Zero-Dependency CLI**: Command-line interface with offline PCAP replay, interface listing, and graceful signal shutdown (`SIGINT`/`SIGTERM`).

### Performance
- **Zero-Allocation Hot Paths**: All L7 dissectors operate at `0 B/op` and `0 allocs/op` via typed metadata structs.
- **Line-Rate Throughput**: Flow lookups run at `38.7 ns/op` (>25.8M flows/sec); PCAP replay runs at `272.3 ns/op` (~3.67M pkts/sec).
- **Concurrency**: 100% data-race free across all components (`go test -race` clean).
