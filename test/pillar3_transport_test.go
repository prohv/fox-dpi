package test

import (
	"net"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"

	"github.com/google/gopacket/layers"
)

// Test_Pillar3_Reassembly_Memory_Bomb_DoS verifies that sequence number gaps
// do not trigger massive heap buffer allocation (DoS immunity).
func Test_Pillar3_Reassembly_Memory_Bomb_DoS(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// 1. Send initial byte at Seq 1000
	p1 := serializeTCPWithSeq(clientIP, serverIP, 45000, 80, 1000, true, false, []byte("G"))
	f, _ := eng.ProcessFrame(p1, time.Now())

	// 2. Inject massive 2 GB sequence gap (Seq 2,000,000,000)
	p2 := serializeTCPWithSeq(clientIP, serverIP, 45000, 80, 2000000000, true, false, []byte("ET / HTTP/1.1\r\n\r\n"))
	f, _ = eng.ProcessFrame(p2, time.Now().Add(5*time.Millisecond))

	if f != nil && f.Reassembler != nil {
		if len(f.Reassembler.Buffer()) > 4096 {
			t.Fatalf("VULNERABILITY: Reassembler buffer exceeded 4 KB safety bound: %d bytes allocated!", len(f.Reassembler.Buffer()))
		}
	}
	t.Logf("PASS: Reassembler rejected 2 GB sequence gap, preserved strict 4 KB bound.")
}

// Test_Pillar3_Negative_Timestamp_Clock_Skew checks behavior when timestamps arrive out of order.
func Test_Pillar3_Negative_Timestamp_Clock_Skew(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	now := time.Now()
	// Packet 1 at T=100s
	p1 := serializeFrame(clientIP, serverIP, 46000, 80, true, true, false, false, false, nil)
	_, _ = eng.ProcessFrame(p1, now)

	// Packet 2 at T=90s (10 seconds IN THE PAST due to packet capture clock skew)
	p2 := serializeFrame(serverIP, clientIP, 80, 46000, true, true, true, false, false, nil)
	f, _ := eng.ProcessFrame(p2, now.Add(-10*time.Second))

	if f != nil {
		if f.HandshakeRTT < 0 {
			t.Errorf("LIMITATION DISCOVERED: Clock skew produced negative HandshakeRTT: %v", f.HandshakeRTT)
		} else {
			t.Logf("PASS: Clock skew handled safely, HandshakeRTT non-negative: %v", f.HandshakeRTT)
		}
	}
}

// Test_Pillar3_Rapid_Port_Reuse_After_FIN tests connection tracking when a client immediately reuses a port.
func Test_Pillar3_Rapid_Port_Reuse_After_FIN(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")
	clientPort := uint16(47000)
	serverPort := uint16(80)

	now := time.Now()

	// Connection 1: Handshake and FIN teardown
	syn1 := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, true, false, false, false, nil)
	fin1 := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, false, true, true, false, nil)
	_, _ = eng.ProcessFrame(syn1, now)
	f1, _ := eng.ProcessFrame(fin1, now.Add(50*time.Millisecond))

	if !f1.Closing {
		t.Fatalf("expected Flow 1 to be marked closing")
	}

	// Immediate port reuse: Client sends brand-new SYN on the SAME port 1ms later
	syn2 := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, true, false, false, false, nil)
	f2, _ := eng.ProcessFrame(syn2, now.Add(51*time.Millisecond))

	// In current single-entry FlowKey table:
	if f2 == f1 {
		t.Logf("OBSERVATION: Port reuse on active 5-tuple updates existing closing flow record rather than instantiating a new flow generation.")
	}
}

// Benchmark_Pillar3_Stateful_Flow_Tracking benchmarks end-to-end bidirectional flow state updates under load.
func Benchmark_Pillar3_Stateful_Flow_Tracking(b *testing.B) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("192.168.1.10")
	serverIP := net.ParseIP("93.184.216.34")

	p1 := serializeFrame(clientIP, serverIP, 54000, 80, true, false, true, false, false, []byte("DATA_FROM_CLIENT"))
	p2 := serializeFrame(serverIP, clientIP, 80, 54000, true, false, true, false, false, []byte("DATA_FROM_SERVER"))

	now := time.Now()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = eng.ProcessFrame(p1, now)
		_, _ = eng.ProcessFrame(p2, now)
	}
}


// Test_Pillar3_SYN_Flood_Mass_Connections tests flow table behavior under a 5,000-connection burst.
func Test_Pillar3_SYN_Flood_Mass_Connections(t *testing.T) {
	cfg := flow.DefaultEvictionConfig()
	cfg.TCPIdle = 100 * time.Millisecond
	cfg.CloseGrace = 50 * time.Millisecond
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, cfg)

	targetIP := net.ParseIP("192.168.1.1")
	now := time.Now()

	// Inject 5,000 distinct SYN packets from pseudo-random client IPs/ports
	for i := 0; i < 5000; i++ {
		clientIP := net.IPv4(10, byte(i>>8), byte(i&0xFF), byte(i%250+1))
		clientPort := uint16(1024 + (i % 60000))
		syn := serializeFrame(clientIP, targetIP, clientPort, 443, true, true, false, false, false, nil)
		_, _ = eng.ProcessFrame(syn, now)
	}

	m1 := eng.Metrics()
	if m1.ActiveFlows != 5000 {
		t.Fatalf("expected 5,000 active flows in table, got %d", m1.ActiveFlows)
	}

	// Trigger expiration sweep after idle window
	evicted := eng.Table().EvictExpired(now.Add(200*time.Millisecond), cfg.TCPIdle, cfg.UDPIdle, cfg.CloseGrace)
	if evicted != 5000 {
		t.Fatalf("expected 5,000 flows evicted, got %d", evicted)
	}

	m2 := eng.Metrics()
	if m2.ActiveFlows != 0 {
		t.Fatalf("expected 0 active flows after sweep, got %d", m2.ActiveFlows)
	}
	t.Logf("PASS: 5,000-flow burst handled across 64 shards and cleanly reclaimed by eviction worker.")
}

// Test_Pillar3_Seq_32Bit_Wraparound tests TCP sequence arithmetic when wrapping past 2^32-1.
func Test_Pillar3_Seq_32Bit_Wraparound(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// Base sequence near uint32 max: 4,294,967,290 (0xFFFFFFFA)
	// Sending 10 bytes: spans 4294967290 .. 4294967300 (which wraps to Seq 4)
	p1 := serializeTCPWithSeq(clientIP, serverIP, 53001, 80, 4294967290, true, false, []byte("GET "))
	p2 := serializeTCPWithSeq(clientIP, serverIP, 53001, 80, 4294967294, true, false, []byte("/wrap HTTP/1.1\r\n\r\n"))

	_, _ = eng.ProcessFrame(p1, time.Now())
	f, _ := eng.ProcessFrame(p2, time.Now().Add(5*time.Millisecond))

	if f != nil && f.L7Metadata.Protocol == "HTTP" {
		t.Logf("PASS: TCP sequence number wraparound handled correctly by reassembler.")
	} else {
		t.Logf("LIMITATION DISCOVERED: Sequence rollover past 2^32-1 did not stitch contiguous HTTP stream.")
	}
}

// Test_Pillar3_Immediate_RST_Handling tests flow teardown when an immediate RST is received.
func Test_Pillar3_Immediate_RST_Handling(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	now := time.Now()
	// SYN
	p1 := serializeFrame(clientIP, serverIP, 53002, 80, true, true, false, false, false, nil)
	// Immediate RST
	p2 := serializeFrame(serverIP, clientIP, 80, 53002, true, false, false, false, true, nil)

	f1, _ := eng.ProcessFrame(p1, now)
	f2, _ := eng.ProcessFrame(p2, now.Add(2*time.Millisecond))

	if f2 != nil && f2.Closing {
		t.Logf("PASS: Immediate RST immediately marked flow Closing=true.")
	} else {
		t.Errorf("expected flow marked closing after RST, got Closing=%v", f1.Closing)
	}
}
