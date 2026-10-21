# Fox DPI 🦊

> High-Performance Passive Layer 7 Deep Packet Inspection Engine in Go.

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/badge/release-v0.1.1-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero-Alloc](https://img.shields.io/badge/Hot_Path-Zero--Alloc-brightgreen.svg)]()
[![Race-Free](https://img.shields.io/badge/Concurrency-100%25_Race--Free-success.svg)]()

Fox DPI is a lightweight, line-rate passive Deep Packet Inspection (DPI) engine written in Go. It reconstructs transport flows and inspects unencrypted Layer 7 metadata (TLS SNI hostnames, HTTP request targets, DNS QNames) in sub-microsecond time without terminating TLS sessions, proxying traffic, or installing root CA certificates on endpoints.

---

## Architecture

```
       Fox DPI Ingestion Pipeline
┌───────────────────────────────────────┐
│ Ingestion: Native Raw / Live / PCAP   │
└───────────────────┬───────────────────┘
                    ▼
┌───────────────────────────────────────┐
│ Zero-Copy Layer Decapsulation         │
│ Ethernet -> IPv4/IPv6 -> TCP/UDP      │
└───────────────────┬───────────────────┘
                    ▼
┌───────────────────────────────────────┐
│ Canonical 64-Shard Flow Table         │
│ Key: Canonical 5-Tuple (Low/High)     │
│ Bidirectional Tracking & RTT Metrics  │
└───────────────────┬───────────────────┘
                    ▼
┌───────────────────────────────────────┐
│ Layer 7 Protocol Dispatcher           │
│ Fast Magic Prefix & Bounded Scan      │
├───────────────────┬───────────────────┤
│ TLS ClientHello   │ HTTP/1.1 Scanner  │
│ (SNI / Direct-IP) │ (Target / Host)   │
├───────────────────┴───────────────────┤
│ DNS Dissector & Shannon Entropy LUT   │
└───────────────────┬───────────────────┘
                    ▼
┌───────────────────────────────────────┐
│ Asynchronous Telemetry Sink           │
│ Non-blocking flows.jsonl / alerts.json│
│ Automatic Rotation & Gzip Compression │
└───────────────────────────────────────┘
```

---

## Core Capabilities

### 1. Passive Layer 7 Protocol Dissection
* **TLS Inspection Without Interception**: Extracts TLS ClientHello SNI hostnames, TLS record versions (1.0 through 1.3), and cipher suites without MITM proxying or TLS decryption.
* **Direct-IP HTTPS Detection**: Identifies TLS handshakes lacking SNI extensions, distinguishing legitimate multi-tenant web traffic from direct IP connections often used by malware C2 implants.
* **HTTP/1.1 Header Dissection**: Extracts request methods (`GET`, `POST`, `HEAD`, `PUT`, etc.), URI targets, User-Agent strings, and Host headers directly from raw wire segments.
* **Bracketed IPv6 Address Handling**: Compliant with RFC 3986 and RFC 7230, preserving full bracketed IPv6 address literals (`[2001:db8::1]`) without truncation at port colons.
* **DNS Query Parsing**: Zero-copy label extraction supporting standard queries, responses, and RFC 1035 compression pointer traversals with loop protection.

### 2. Adversarial Evasion & Attack Defenses
* **Protocol Padding Evasion Defense**: Bounded 64-byte sliding-window scanner detecting TLS and HTTP payloads obscured behind junk noise bytes (MITRE ATT&CK T1001.003).
* **HTTP Request Smuggling Defense**: Enforces RFC 7230 Section 5.4 first-host-wins and alerts on duplicate `Host` headers (`HTTP_DUPLICATE_HOST`), thwarting CWE-444 request smuggling and cache poisoning.
* **High-Port TLS C2 Detection**: Flags encrypted TLS handshakes operating on non-standard ports (e.g., 4444, 1337) used by command-and-control frameworks (Cobalt Strike, Metasploit, Sliver), while preserving a 1-cycle fast path on ports 443/8443.
* **Port Spoofing Detection**: Alerts when plaintext HTTP is transmitted on HTTPS port 443, or encrypted TLS is transmitted on plain HTTP port 80.
* **Bidirectional Center-Out Stream Reassembly**: 8 KB reassembly buffer (4 KB Headroom / 4 KB Tailroom) accommodating reverse packet arrivals and mid-stream capture drops without memory copies.

### 3. Threat Intelligence & Exfiltration Detection
* **Line-Rate Shannon Entropy**: Precomputed logarithmic lookup table (LUT) calculating exact Shannon entropy on DNS subdomains with a 2ns length gate to detect encrypted DNS tunneling exfiltration (MITRE ATT&CK T1071.004).
* **Domain Generation Algorithm (DGA) Defense**: Bounded 16-shard `StringInterner` safely caches high-churn domain queries without memory leaks or lock contention.

### 4. Transport & Flow Lifecycle Management
* **Rapid Port Reuse Epoch Renewal**: Immediately finalizes closing flow records and instantiates fresh flow epochs upon receiving a new `SYN` on a teardown 5-tuple, preventing `L7Bypass` evasion.
* **Monotonic Arrival Envelope**: Monotonically bounds `FirstSeen` and `LastSeen` timestamps, guaranteeing non-negative connection durations even under multi-queue NIC hardware timestamp skew.
* **32-Bit Sequence Wraparound**: Modular sequence arithmetic handling sequence rollover past $2^{32}-1$.
* **Stateful Metrics**: Tracks handshake RTT, bidirectional packet/byte counts, active duration, and connection teardown states (FIN/RST).

---

## Performance Benchmarks

All microbenchmarks and end-to-end tests run with **zero heap allocations on hot paths** on an Intel Core i7-13620H:

| Engine Component | Latency | Throughput |
| :--- | :--- | :--- |
| **TLS Dissector** | **51.8 ns/op** | ~19.3M ops/sec |
| **DNS Dissector** | **62.4 ns/op** | ~16.0M ops/sec |
| **HTTP Dissector** | **235.1 ns/op** | ~4.25M ops/sec |
| **Protocol Fast Rejection Gate** | **24.7 ns/op** | ~40.5M ops/sec |
| **Shannon Entropy LUT (Port 53)** | **175.7 ns/op** | ~5.69M ops/sec |
| **FlowTable Parallel Lookups** | **38.7 ns/op** | **>25.8M flows/sec** |
| **PCAP End-to-End Engine Replay** | **272.3 ns/op** | **~3.67M packets/sec** |

*All components operate with **zero heap allocations (0 B/op, 0 allocs/op)** on hot paths and are 100% data-race free (`go test -race ./...`).*

---

## Installation & Build

### Prerequisites
* Go 1.24 or higher
* Windows, Linux, or macOS

### Build from Source
```bash
git clone https://github.com/example/fox-dpi.git
cd fox-dpi
go build -o foxdpi.exe ./cmd/foxdpi
```

---

## CLI Usage

### 1. Live Packet Capture (Out-of-the-Box)

Zero dependencies required (no Npcap or Wireshark needed). Fox DPI binds natively to host OS kernel raw packet taps:

```bash
# Auto-detect active Wi-Fi or primary Ethernet and capture live
foxdpi -i capture

# Capture on a specific network adapter (e.g., Wi-Fi, eth0, en0)
foxdpi -i Wi-Fi

# List all available network adapters with IP and MAC info
foxdpi -list
```

> [!NOTE]
> **OS Privilege Requirements for Live Capture**:
> - **Windows**: Run terminal as **Administrator** (Winsock2 `SIO_RCVALL` raw socket).
> - **Linux**: Run with `sudo` or file capability: `sudo setcap cap_net_raw=eip ./foxdpi` (`AF_PACKET`).
> - **macOS**: Run with `sudo ./foxdpi` (Berkeley Packet Filter `/dev/bpf*`).

### 2. Analyze Offline PCAP File
```bash
foxdpi -f /path/to/traffic.pcap -o ./output -rotate-mb 10
```

### CLI Command Reference
```
Fox DPI - Passive Layer 7 Deep Packet Inspection Engine

Usage:
  foxdpi -i capture                   # Auto-detect active Wi-Fi/Ethernet and capture live
  foxdpi -i <iface>                   # Capture live on specific interface (e.g. -i Wi-Fi)
  foxdpi -f <path.pcap> [-o <out_dir>] # Replay and analyze offline PCAP
  foxdpi -list                        # List available network interfaces
  foxdpi -version                     # Print version and exit

Flags:
  -f string
        Path to PCAP file for offline analysis
  -i string
        Interface to capture live ('capture' for auto-detection, e.g. -i capture, -i Wi-Fi)
  -o string
        Directory to store flows.jsonl and alerts.jsonl (default "output")
  -rotate-mb int
        Maximum telemetry file size in MB before gzip rotation (default 10)
  -list
        List available network interfaces and exit
  -version
        Print foxdpi version and exit
```

### Live Alerting & Session Summary

During live capture, security alerts stream directly to the terminal in real time while asynchronous telemetry writes to `output/flows.jsonl` and `output/alerts.jsonl`. Pressing `Ctrl+C` prints an operational summary:

```
[ALERT] [HIGH] SUSPICIOUS_HIGH_PORT_TLS: TLS handshake on non-standard port
        Endpoints: 172.17.214.61:54200 -> 185.220.101.5:4444 (TLS)
^C
==================================================
               FOX-DPI RUN SUMMARY                
==================================================
 Capture Mode            : Live Capture on Wi-Fi [Data Link: IPv4]
 Total Packets Processed : 42,810
 Total Volume Captured   : 38.4 MB
 Packet Loss / Errors    : 0
--------------------------------------------------
 Flows Emitted to Sink   : 184
 Active Flows at Exit    : 64
 Security Alerts Fired   : 1
 Dropped Sink Events     : 0
--------------------------------------------------
 Telemetry Output Dir    : output/
 Elapsed Run Time        : 1m15s
 Processing Throughput   : 570 pkts/sec
==================================================
```

---

## Telemetry Formats

Telemetry is streamed asynchronously using non-blocking channels into split JSON Lines files:

### 1. Flow Event (`flows.jsonl`)
Emitted when a TCP connection finishes teardown or an idle flow expires:
```json
{
  "timestamp": "2026-10-20T12:00:00.123456789Z",
  "src_ip": "192.168.1.50",
  "dst_ip": "140.82.121.4",
  "src_port": 54000,
  "dst_port": 443,
  "protocol": "TCP",
  "l7_protocol": "TLS",
  "host": "api.github.com",
  "packets": 18,
  "bytes": 4820,
  "duration_ms": 142,
  "handshake_ms": 28,
  "details": {
    "sni": "api.github.com",
    "version": "TLS 1.2/1.3"
  }
}
```

### 2. Alert Event (`alerts.jsonl`)
Emitted immediately upon identifying an anomalous or adversarial pattern:
```json
{
  "timestamp": "2026-10-20T12:00:01.987654321Z",
  "rule": "SUSPICIOUS_HIGH_PORT_TLS",
  "severity": "HIGH",
  "src_ip": "192.168.1.100",
  "dst_ip": "185.220.101.5",
  "src_port": 49200,
  "dst_port": 4444,
  "protocol": "TCP",
  "message": "Encrypted TLS traffic detected on non-standard port 4444",
  "details": {
    "sni": "none",
    "version": "TLS 1.2/1.3"
  }
}
```

---

## Testing & Quality Assurance

Run the comprehensive unit, integration, and security test suite:
```bash
# Run all tests with race detector
go test -v -race ./...

# Run benchmarks with memory allocation metrics
cd test && go test -bench=. -benchmem
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
