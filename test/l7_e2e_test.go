package test

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
)

func Test_Engine_L7_DeepInspection_E2E(t *testing.T) {
	pcapPath := filepath.Join("testdata", "l7_traffic.pcap")
	if err := GenerateL7TrafficPCAP(pcapPath); err != nil {
		t.Fatalf("failed to generate l7 pcap: %v", err)
	}

	src, err := capture.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("failed to open l7 pcap: %v", err)
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

	clientIP := netip.MustParseAddr("192.168.1.50")
	dnsIP := netip.MustParseAddr("1.1.1.1")
	githubIP := netip.MustParseAddr("140.82.121.4")
	webIP := netip.MustParseAddr("93.184.216.34")
	spoofIP := netip.MustParseAddr("198.51.100.1")

	// 1. Verify DNS Query Dissection
	keyDNS := flow.NewFlowKey(clientIP, 53000, dnsIP, 53, 17)
	flowDNS, exists := eng.Table().Get(keyDNS)
	if !exists {
		t.Fatal("expected DNS flow to exist")
	}
	if flowDNS.L7Metadata.Protocol != "DNS" || flowDNS.L7Metadata.Host != "api.github.com" {
		t.Fatalf("unexpected DNS metadata: %+v", flowDNS.L7Metadata)
	}

	// 2. Verify Fragmented TLS ClientHello across segments
	keyTLS := flow.NewFlowKey(clientIP, 54000, githubIP, 443, 6)
	flowTLS, exists := eng.Table().Get(keyTLS)
	if !exists {
		t.Fatal("expected TLS flow to exist")
	}
	if flowTLS.L7Metadata.Protocol != "TLS" || flowTLS.L7Metadata.Host != "api.github.com" {
		t.Fatalf("expected reassembled SNI api.github.com, got: %+v", flowTLS.L7Metadata)
	}
	if !flowTLS.L7Bypass {
		t.Fatal("expected TLS flow to have L7Bypass enabled after handshake")
	}

	// 3. Verify HTTP/1.1 Keep-Alive Session
	keyHTTP := flow.NewFlowKey(clientIP, 52000, webIP, 80, 6)
	flowHTTP, exists := eng.Table().Get(keyHTTP)
	if !exists {
		t.Fatal("expected HTTP flow to exist")
	}
	if flowHTTP.L7Metadata.Protocol != "HTTP" {
		t.Fatalf("expected HTTP protocol, got %s", flowHTTP.L7Metadata.Protocol)
	}
	if flowHTTP.L7Bypass {
		t.Fatal("expected HTTP keep-alive flow to have L7Bypass disabled")
	}

	// 4. Verify Evasion: TLS ClientHello on port 8080 (Non-standard port)
	keySpoofTLS := flow.NewFlowKey(clientIP, 55000, spoofIP, 8080, 6)
	flowSpoofTLS, exists := eng.Table().Get(keySpoofTLS)
	if !exists {
		t.Fatal("expected spoofed TLS flow on port 8080 to exist")
	}
	if flowSpoofTLS.L7Metadata.Protocol != "TLS" || flowSpoofTLS.L7Metadata.Host != "evasion-test.cloudflare.com" {
		t.Fatalf("expected port-spoofed TLS to extract evasion-test.cloudflare.com, got: %+v", flowSpoofTLS.L7Metadata)
	}

	// 5. Verify Evasion: HTTP on high port 54321
	keySpoofHTTP := flow.NewFlowKey(clientIP, 56000, spoofIP, 54321, 6)
	flowSpoofHTTP, exists := eng.Table().Get(keySpoofHTTP)
	if !exists {
		t.Fatal("expected spoofed HTTP flow on port 54321 to exist")
	}
	if flowSpoofHTTP.L7Metadata.Protocol != "HTTP" || flowSpoofHTTP.L7Metadata.Host != "custom-proxy.net" {
		t.Fatalf("expected port-spoofed HTTP to extract custom-proxy.net, got: %+v", flowSpoofHTTP.L7Metadata)
	}
}

func Benchmark_Engine_L7_DeepInspection(b *testing.B) {
	pcapPath := filepath.Join("testdata", "l7_traffic.pcap")
	_ = GenerateL7TrafficPCAP(pcapPath)

	src, err := capture.OpenOffline(pcapPath)
	if err != nil {
		b.Fatalf("failed to open l7 pcap: %v", err)
	}
	defer src.Close()

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
