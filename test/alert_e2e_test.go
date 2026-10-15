package test

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
	"fox-dpi/internal/sink"

	"github.com/google/gopacket/layers"
)

func Test_Engine_Alerts_And_Sink_E2E(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_e2e_sink_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pcapPath := filepath.Join(tempDir, "l7_traffic.pcap")
	if err := GenerateL7TrafficPCAP(pcapPath); err != nil {
		t.Fatalf("failed to generate L7 PCAP: %v", err)
	}

	sinkCfg := sink.DefaultFileSinkConfig(tempDir)
	sinkCfg.CompressOnRotate = false
	fs, err := sink.NewFileSink(sinkCfg)
	if err != nil {
		t.Fatalf("failed to create file sink: %v", err)
	}

	src, err := capture.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("failed to open PCAP: %v", err)
	}
	defer src.Close()

	eng, err := engine.NewEngine(src.LinkType(), flow.DefaultEvictionConfig(), fs)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	ctx := context.Background()
	if err := eng.Run(ctx, src); err != nil {
		t.Fatalf("engine run failed: %v", err)
	}

	// Close engine to drain remaining flows to sink
	if err := eng.Close(); err != nil {
		t.Fatalf("engine close failed: %v", err)
	}

	m := eng.Metrics()
	if m.TotalPackets == 0 {
		t.Fatalf("expected packets > 0, got 0")
	}
	if m.EmittedFlows == 0 {
		t.Fatalf("expected emitted flows > 0, got 0")
	}
	if m.EmittedAlerts == 0 {
		t.Fatalf("expected emitted alerts > 0, got 0")
	}

	// Verify alerts.jsonl has the PORT_SPOOF_TLS alert
	alertFile, err := os.Open(filepath.Join(tempDir, "alerts.jsonl"))
	if err != nil {
		t.Fatalf("failed to open alerts.jsonl: %v", err)
	}
	defer alertFile.Close()

	var foundSpoofTLS bool
	scanner := bufio.NewScanner(alertFile)
	for scanner.Scan() {
		var a sink.AlertEvent
		if err := json.Unmarshal(scanner.Bytes(), &a); err != nil {
			t.Fatalf("failed to parse alert json: %v", err)
		}
		if a.Rule == "PORT_SPOOF_TLS" && a.DstPort == 8080 {
			foundSpoofTLS = true
		}
	}
	if !foundSpoofTLS {
		t.Errorf("expected PORT_SPOOF_TLS alert on port 8080, but not found in alerts.jsonl")
	}

	// Verify flows.jsonl contains expected L7 protocol flows
	flowFile, err := os.Open(filepath.Join(tempDir, "flows.jsonl"))
	if err != nil {
		t.Fatalf("failed to open flows.jsonl: %v", err)
	}
	defer flowFile.Close()

	var countDNS, countTLS, countHTTP int
	fScanner := bufio.NewScanner(flowFile)
	for fScanner.Scan() {
		var f sink.FlowEvent
		if err := json.Unmarshal(fScanner.Bytes(), &f); err != nil {
			t.Fatalf("failed to parse flow json: %v", err)
		}
		switch f.L7Protocol {
		case "DNS":
			countDNS++
		case "TLS":
			countTLS++
		case "HTTP":
			countHTTP++
		}
	}

	if countDNS == 0 || countTLS == 0 || countHTTP == 0 {
		t.Errorf("expected flows for DNS, TLS, HTTP; got DNS=%d, TLS=%d, HTTP=%d", countDNS, countTLS, countHTTP)
	}
}

func Test_Engine_PortSpoof_HTTP_Alert(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_spoof_http_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sinkCfg := sink.DefaultFileSinkConfig(tempDir)
	fs, err := sink.NewFileSink(sinkCfg)
	if err != nil {
		t.Fatalf("failed to create file sink: %v", err)
	}

	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), fs)
	if err != nil {
		t.Fatalf("failed to initialize engine: %v", err)
	}

	// Send HTTP plaintext request to port 443
	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")
	httpReq := []byte("GET /sensitive-data HTTP/1.1\r\nHost: secure.corp\r\n\r\n")

	pkt1 := serializeFrame(clientIP, serverIP, 41000, 443, true, true, false, false, false, nil)
	pkt2 := serializeTCPWithSeq(clientIP, serverIP, 41000, 443, 1000, true, false, httpReq)

	now := time.Now()
	_, _ = eng.ProcessFrame(pkt1, now)
	_, _ = eng.ProcessFrame(pkt2, now.Add(10*time.Millisecond))

	_ = eng.Close()

	alertFile, err := os.Open(filepath.Join(tempDir, "alerts.jsonl"))
	if err != nil {
		t.Fatalf("failed to open alerts.jsonl: %v", err)
	}
	defer alertFile.Close()

	var foundHttpSpoof bool
	scanner := bufio.NewScanner(alertFile)
	for scanner.Scan() {
		var a sink.AlertEvent
		if err := json.Unmarshal(scanner.Bytes(), &a); err != nil {
			t.Fatalf("failed to parse alert json: %v", err)
		}
		if a.Rule == "PORT_SPOOF_HTTP" && a.DstPort == 443 && a.Severity == "HIGH" {
			foundHttpSpoof = true
		}
	}
	if !foundHttpSpoof {
		t.Errorf("expected PORT_SPOOF_HTTP alert on port 443")
	}
}
