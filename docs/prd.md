# PRD: Fox DPI — Go Deep Packet Inspection Engine

## 1. System Overview & Architectural Model

Fox DPI is a passive, developer-oriented Deep Packet Inspection (DPI) engine written in Go. It reconstructs transport flows and inspects unencrypted Layer 7 application metadata (DNS queries, TLS SNI hostnames, HTTP request targets) without terminating TLS sessions or installing local root certificates.

```
[ Ingestion: libpcap / offline .pcap / AF_PACKET ]
                      │
                      ▼
         [ Layer Decapsulation ]
      Ethernet ➔ IPv4/IPv6 ➔ TCP/UDP
                      │
                      ▼
           [ Canonical Flow Table ]
     Key: 5-tuple | Concurrent Sharded Map
         Directional Tracking & Metrics
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
   [ UDP Path ]                [ TCP Path ]
Stateless dissection    Stream Reassembly (tcpassembly)
        │                           │
        └─────────────┬─────────────┘
                      ▼
          [ Layer 7 Dissectors ]
        Magic-byte prefix match ➔ TLV parse
        (DNS, TLS ClientHello SNI, HTTP/1.1)
                      │
                      ▼
      [ Telemetry Sink / Policy Engine ]
         JSON Events / Egress Rules / TUI

```

---

## 2. Core Data Contracts

### 2.1 Canonical 5-Tuple Flow Key

Connections are bidirectional; client-to-server and server-to-client frames must resolve to the identical flow record.

```go
type FlowKey struct {
    LowIP    netip.Addr
    HighIP   netip.Addr
    LowPort  uint16
    HighPort uint16
    Proto    uint8 // IP protocol number (6=TCP, 17=UDP)
}

// Invariant: LowIP < HighIP. If LowIP == HighIP, LowPort <= HighPort.

```

### 2.2 L7 Dissector Contract

Every protocol parser implements a zero-allocation matching interface:

```go
type Verdict uint8
const (
    VerdictUnknown Verdict = iota
    VerdictNeedMoreData
    VerdictMatched
)

type Metadata struct {
    Protocol string            // "DNS", "TLS", "HTTP"
    Host     string            // Extracted hostname / SNI / QNAME
    Details  map[string]string // Method, Cipher, QueryType
}

type Dissector interface {
    Name() string
    Inspect(payload []byte, dir Direction) (Verdict, Metadata, error)
}

```

---

## 3. Phase 1: Ingestion, Decapsulation & Flow Tracking

### Scope & Deliverables

* **Packet Ingestion Boundary:** Implement a `PacketSource` interface wrapping `gopacket/pcap` to read seamlessly from either live network adapters (`eth0`, `lo0`) or offline `.pcap` files.
* **Header Decapsulation:** Walk Ethernet $\rightarrow$ IPv4/IPv6 $\rightarrow$ TCP/UDP. Drop corrupted frames. Extract payload byte slices without heap allocation.
* **Flow State Table:** Concurrent-safe hash map storing flow records. Track metrics:
* Packets Sent / Received
* Bytes Sent / Received
* Connection Start Timestamp (`FirstSeen`) and Last Active Timestamp (`LastSeen`)


* **State Expiration:** Background ticker goroutine evicting dead flows after an idle timeout window (e.g., 30s TCP idle, 5s UDP idle).

### Acceptance Tests

* `Test_FlowKey_CanonicalInvariance`: Packet `(IP_A:1234 -> IP_B:80)` and Packet `(IP_B:80 -> IP_A:1234)` generate the identical hash and struct equality.
* `Test_Decapsulation_MalformedHeaders`: Truncated IP/TCP byte slices return designated parsing errors instead of triggering slice-boundary runtime panics.
* `Test_PCAP_FixtureValidation`: Replay a 50-packet standard capture; assert final flow table packet/byte counters match Wireshark conversation statistics with zero drift.

---

## 4. Phase 2: TCP Stream Reassembly & L7 Dissectors

### Scope & Deliverables

* **TCP Stream Reassembly:** Integrate `gopacket/tcpassembly` to resolve out-of-order delivery, sequence gaps, duplicate ACKs, and window segmentation into a sequential stream reader.
* **Dissector Dispatcher:** Fast prefix-matching engine that dispatches the first $N$ bytes (up to 512 bytes) to registered parsers.
* **Protocol Dissector Implementations:**
1. **DNS (UDP):** Parse DNS header flags, question records, and decode length-prefixed QNAME labels into domain strings (e.g., `\x03foo\x03bar\x00` $\rightarrow$ `foo.bar`).
2. **TLS ClientHello (TCP):**
* Match record magic bytes: `0x16 0x03` (Handshake record + SSL 3.0 / TLS 1.X).
* Verify handshake type `0x01` (`ClientHello`).
* Skip: Client Random (32 bytes), Session ID length vector, Cipher Suite length vector, Compression Methods vector.
* Parse Extension TLVs: Locate extension type `0x00 0x00` (Server Name Indication).
* Extract host name bytes.


3. **HTTP/1.1 (TCP):**
* Detect ASCII verb prefixes: `GET `, `POST `, `PUT `, `DELETE `, `HEAD `, `OPTIONS `.
* Parse headers up to `\r\n\r\n`. Extract `Host:` and `User-Agent:` values.





### Acceptance Tests

* `Test_TLS_SNI_GoldenVectors`: Feed known raw ClientHello hex fixtures from TLS 1.2 and TLS 1.3 handshakes; verify exact SNI domain extraction.
* `Test_TCP_Out_Of_Order_Reassembly`: Split an HTTP GET payload across three TCP segments; inject in reverse order (`Seq 3`, `Seq 2`, `Seq 1`). Assert dissector fires only when reassembly is contiguous.
* `Test_Truncated_Extensions`: Supply malformed TLS packets where extension declared length exceeds buffer length; verify graceful `VerdictNeedMoreData` or error, never a panic.

---

## 5. Phase 3: High-Throughput Pipeline & Traffic Simulation

### Scope & Deliverables

* **Flow Table Sharding:** Replace single global `sync.RWMutex` with a striped map (e.g., 64/128 shards indexed by `hash(FlowKey) % NumShards`) to eliminate lock contention.
* **Zero-Allocation Pools:** Implement `sync.Pool` for packet byte buffers and reassembly nodes to eliminate garbage collection pauses under high packet arrival rates.
* **Structured Output Pipeline:** Emit flow completion events in structured JSON format (`timestamp`, `5-tuple`, `protocol`, `target_host`, `bytes_in`, `bytes_out`, `duration_ms`).

### Performance & Simulation Architecture

```
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│     k6 Traffic Generator        │ ────► │     Local Mock Servers          │
│ (Concurrent HTTP + TLS queries) │       │ (HTTPS :8443, HTTP :8080, DNS)  │
└─────────────────────────────────┘       └─────────────────────────────────┘
                                                           │
                                                  [ Loopback Adapter ]
                                                           │
                                                           ▼
                                          ┌─────────────────────────────────┐
                                          │       Fox DPI Engine            │
                                          │  Captures lo0 -> Sharded Maps   │
                                          └─────────────────────────────────┘

```

### Verification & Benchmarking Matrix

* **Deterministic Replay:** Replay captured multi-megabyte PCAP files via `tcpreplay` on a virtual interface (`veth`) at 100k packets per second. Verify zero dropped packets via `pcap_stats`.
* **Concurreny Stress Test via k6:** Run a 5-minute k6 load script generating concurrent HTTPS requests across distinct hostnames. Assert 100% SNI detection rate with no dropped flows.
* **Profiling Standards:** Profile via `go tool pprof` during load:
* Heap allocations per packet must approach zero in the hot path.
* GC CPU usage must remain $< 5\%$ of total runtime.



---

## 6. Post-Phase 3 Product Extension Paths

Once the core engine completes Phase 3, choose one specialization track:

| Product Track | Core Value Proposition | Key Architectural Requirement |
| --- | --- | --- |
| **A. Container Egress Auditor** | Zero-config audit CLI detecting unauthorized third-party telemetry and leaks during local dev. | Network namespace capture (`ip netns exec`) or eBPF socket filters to scope sniffing to a single PID/container. |
| **B. CI/CD Security Gatekeeper** | Automated gatekeeper CLI failing CI builds if tests make unapproved outbound connections. | Policy configuration parser (`rules.yaml`) + deterministic process wrapper (`foxdpi exec -- <cmd>`) returning exit codes. |
| **C. Terminal Observability TUI** | Real-time terminal network monitor (modern Wireshark alternative for devs). | Decoupled event-bus queue connecting the packet engine to a Bubble Tea TUI renderer without dropping capture packets. |

---

## 7. Engineering Constraints & Rules of Engagement

1. **No Application Decryption:** Never implement TLS MITM decryption or local CA cert generation. Rely strictly on plaintext handshakes (DNS, SNI, HTTP).
2. **Buffer Safety:** No slicing without bounds checks. Guard all raw binary offsets with minimum length verifications before dereferencing byte ranges.
3. **Goroutine Isolation:** The capture loop must only decapsulate and route to shard workers. Never run complex string parsing or regex inside the ingestion loop.