package test

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
)

func TestMain(m *testing.M) {
	pcapPath := filepath.Join("testdata", "sample.pcap")
	if err := GenerateSamplePCAP(pcapPath); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll("testdata")
	os.Exit(code)
}

func Test_Engine_PCAP_Replay_E2E(t *testing.T) {
	pcapPath := filepath.Join("testdata", "sample.pcap")
	src, err := capture.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("failed to open offline pcap: %v", err)
	}
	defer src.Close()

	eng, err := engine.NewEngine(src.LinkType(), flow.DefaultEvictionConfig())
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	ctx := context.Background()
	if err := eng.Run(ctx, src); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	m := eng.Metrics()
	if m.TotalPackets != 50 {
		t.Fatalf("expected 50 packets processed, got %d", m.TotalPackets)
	}
	if m.DropPackets != 0 {
		t.Fatalf("expected 0 dropped packets, got %d", m.DropPackets)
	}
	if m.ActiveFlows != 11 {
		t.Fatalf("expected 11 active flows, got %d", m.ActiveFlows)
	}

	// Verify Flow 1 (HTTP)
	clientIP := netip.MustParseAddr("192.168.1.50")
	webIP := netip.MustParseAddr("93.184.216.34")
	key1 := flow.NewFlowKey(clientIP, 52000, webIP, 80, 6)
	f1, exists := eng.Table().Get(key1)
	if !exists {
		t.Fatal("expected flow 1 (HTTP) to exist in table")
	}
	if f1.ClientPackets+f1.ServerPackets != 10 {
		t.Fatalf("expected 10 packets in flow 1, got %d", f1.ClientPackets+f1.ServerPackets)
	}
	if !f1.Closing {
		t.Fatal("expected flow 1 to be marked Closing due to FIN flag")
	}

	// Verify Flow 2 (DNS)
	dnsIP := netip.MustParseAddr("8.8.8.8")
	key2 := flow.NewFlowKey(clientIP, 53000, dnsIP, 53, 17)
	f2, exists := eng.Table().Get(key2)
	if !exists {
		t.Fatal("expected flow 2 (DNS) to exist in table")
	}
	if f2.ClientPackets != 1 || f2.ServerPackets != 1 {
		t.Fatalf("expected 1 query and 1 response in flow 2, got %d / %d", f2.ClientPackets, f2.ServerPackets)
	}

	// Verify Flow 3 (TLS RTT)
	tlsIP := netip.MustParseAddr("1.1.1.1")
	key3 := flow.NewFlowKey(clientIP, 54000, tlsIP, 443, 6)
	f3, exists := eng.Table().Get(key3)
	if !exists {
		t.Fatal("expected flow 3 (TLS) to exist in table")
	}
	if f3.HandshakeRTT != 15*time.Millisecond {
		t.Fatalf("expected 15ms HandshakeRTT, got %v", f3.HandshakeRTT)
	}

	// Test Two-Tier Eviction
	baseTime := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	// After 3 seconds, Flow 1 (FIN seen, 2s grace) must be evicted
	evictedFast := eng.Table().EvictExpired(baseTime.Add(3*time.Second), 30*time.Second, 5*time.Second, 2*time.Second)
	if evictedFast != 1 {
		t.Fatalf("expected 1 flow evicted via fast-path, got %d", evictedFast)
	}
	if eng.Table().Count() != 10 {
		t.Fatalf("expected 10 active flows after fast eviction, got %d", eng.Table().Count())
	}

	// After 35 seconds, all remaining idle flows must be evicted
	evictedIdle := eng.Table().EvictExpired(baseTime.Add(35*time.Second), 30*time.Second, 5*time.Second, 2*time.Second)
	if evictedIdle != 10 {
		t.Fatalf("expected 10 remaining flows evicted, got %d", evictedIdle)
	}
	if eng.Table().Count() != 0 {
		t.Fatalf("expected 0 active flows, got %d", eng.Table().Count())
	}
}

func Benchmark_Engine_PCAP_Replay(b *testing.B) {
	pcapPath := filepath.Join("testdata", "sample.pcap")
	src, err := capture.OpenOffline(pcapPath)
	if err != nil {
		b.Fatalf("failed to open offline pcap: %v", err)
	}
	defer src.Close()

	// Read packets into memory for pure CPU throughput benchmarking
	type packetData struct {
		data []byte
		ts   time.Time
	}
	var packets []packetData
	for {
		data, ci, err := src.ReadPacket()
		if err != nil {
			break
		}
		raw := make([]byte, len(data))
		copy(raw, data)
		packets = append(packets, packetData{data: raw, ts: ci.Timestamp})
	}

	eng, _ := engine.NewEngine(src.LinkType(), flow.DefaultEvictionConfig())

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		p := &packets[i%len(packets)]
		_, _ = eng.ProcessFrame(p.data, p.ts)
	}
}
