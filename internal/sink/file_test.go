package sink

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSink_Basic(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_sink_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := DefaultFileSinkConfig(tempDir)
	cfg.CompressOnRotate = false
	s, err := NewFileSink(cfg)
	if err != nil {
		t.Fatalf("failed to create file sink: %v", err)
	}

	flowEv := FlowEvent{
		Timestamp:  time.Now(),
		SrcIP:      "192.168.1.100",
		DstIP:      "1.1.1.1",
		SrcPort:    54321,
		DstPort:    53,
		Protocol:   "UDP",
		L7Protocol: "DNS",
		Host:       "example.com",
		Packets:    2,
		Bytes:      150,
		DurationMs: 12,
	}
	s.EmitFlow(flowEv)

	alertEv := AlertEvent{
		Timestamp: time.Now(),
		Rule:      "PORT_SPOOF_HTTP",
		Severity:  "WARN",
		SrcIP:     "10.0.0.1",
		DstIP:     "10.0.0.2",
		SrcPort:   12345,
		DstPort:   443,
		Protocol:  "TCP",
		Message:   "Plaintext HTTP detected on HTTPS port 443",
	}
	s.EmitAlert(alertEv)

	if err := s.Close(); err != nil {
		t.Fatalf("sink Close failed: %v", err)
	}

	// Verify flows.jsonl
	flowData, err := os.ReadFile(filepath.Join(tempDir, "flows.jsonl"))
	if err != nil {
		t.Fatalf("failed to read flows.jsonl: %v", err)
	}
	var readFlow FlowEvent
	if err := json.Unmarshal(flowData[:len(flowData)-1], &readFlow); err != nil {
		t.Fatalf("failed to parse flow JSON: %v, raw: %s", err, string(flowData))
	}
	if readFlow.Host != "example.com" || readFlow.L7Protocol != "DNS" {
		t.Errorf("unexpected flow data: %+v", readFlow)
	}

	// Verify alerts.jsonl
	alertData, err := os.ReadFile(filepath.Join(tempDir, "alerts.jsonl"))
	if err != nil {
		t.Fatalf("failed to read alerts.jsonl: %v", err)
	}
	var readAlert AlertEvent
	if err := json.Unmarshal(alertData[:len(alertData)-1], &readAlert); err != nil {
		t.Fatalf("failed to parse alert JSON: %v, raw: %s", err, string(alertData))
	}
	if readAlert.Rule != "PORT_SPOOF_HTTP" {
		t.Errorf("unexpected alert data: %+v", readAlert)
	}

	stats := s.Stats()
	if stats.EmittedFlows != 1 || stats.EmittedAlerts != 1 {
		t.Errorf("unexpected stats: %+v", stats)
	}
}

func TestFileSink_RotationAndCompression(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_rotate_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := FileSinkConfig{
		OutputDir:        tempDir,
		MaxSizeBytes:     300, // Trigger rotation after ~2 events
		BufferSize:       128,
		QueueCapacity:    100,
		CompressOnRotate: true,
	}

	s, err := NewFileSink(cfg)
	if err != nil {
		t.Fatalf("failed to create file sink: %v", err)
	}

	for i := 0; i < 10; i++ {
		s.EmitFlow(FlowEvent{
			Timestamp:  time.Now(),
			SrcIP:      "192.168.1.10",
			DstIP:      "8.8.8.8",
			SrcPort:    uint16(30000 + i),
			DstPort:    53,
			Protocol:   "UDP",
			L7Protocol: "DNS",
			Host:       "google.com",
			Packets:    1,
			Bytes:      60,
		})
	}

	if err := s.Close(); err != nil {
		t.Fatalf("sink Close failed: %v", err)
	}

	entries, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}

	var foundGz bool
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "flows.") && strings.HasSuffix(entry.Name(), ".jsonl.gz") {
			foundGz = true
			// Validate gzip integrity
			f, err := os.Open(filepath.Join(tempDir, entry.Name()))
			if err != nil {
				t.Fatalf("failed to open gz file: %v", err)
			}
			gr, err := gzip.NewReader(f)
			if err != nil {
				t.Fatalf("failed to create gzip reader: %v", err)
			}
			scanner := bufio.NewScanner(gr)
			for scanner.Scan() {
				var fl FlowEvent
				if err := json.Unmarshal(scanner.Bytes(), &fl); err != nil {
					t.Fatalf("failed to unmarshal gzipped json: %v", err)
				}
			}
			_ = gr.Close()
			_ = f.Close()
		}
	}

	if !foundGz {
		t.Errorf("expected rotated .jsonl.gz files, found entries: %+v", entries)
	}
}

func TestFileSink_Backpressure(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_drop_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := FileSinkConfig{
		OutputDir:        tempDir,
		MaxSizeBytes:     1024 * 1024,
		BufferSize:       1024,
		QueueCapacity:    2, // Tiny queue to trigger drops easily
		CompressOnRotate: false,
	}

	s, err := NewFileSink(cfg)
	if err != nil {
		t.Fatalf("failed to create file sink: %v", err)
	}

	// Flood sink rapidly
	for i := 0; i < 5000; i++ {
		s.EmitFlow(FlowEvent{
			Timestamp: time.Now(),
			SrcIP:     "10.0.0.1",
			DstIP:     "10.0.0.2",
			SrcPort:   uint16(1000 + i%1000),
			DstPort:   80,
			Protocol:  "TCP",
		})
	}

	_ = s.Close()
	stats := s.Stats()

	// Some events should be emitted, some dropped, but never deadlocked
	if stats.EmittedFlows == 0 {
		t.Errorf("expected emitted flows > 0, got %d", stats.EmittedFlows)
	}
}

func BenchmarkFileSink_EmitFlow(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "foxdpi_bench_*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfg := DefaultFileSinkConfig(tempDir)
	cfg.CompressOnRotate = false
	s, err := NewFileSink(cfg)
	if err != nil {
		b.Fatalf("failed to create file sink: %v", err)
	}
	defer s.Close()

	ev := FlowEvent{
		Timestamp:  time.Now(),
		SrcIP:      "192.168.1.100",
		DstIP:      "142.250.190.46",
		SrcPort:    51234,
		DstPort:    443,
		Protocol:   "TCP",
		L7Protocol: "TLS",
		Host:       "google.com",
		Packets:    10,
		Bytes:      2400,
		DurationMs: 150,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.EmitFlow(ev)
	}
}

func Benchmark_JSON_Stdlib_Marshal(b *testing.B) {
	ev := FlowEvent{
		Timestamp:   time.Now(),
		SrcIP:       "192.168.1.100",
		DstIP:       "142.250.190.46",
		SrcPort:     51234,
		DstPort:     443,
		Protocol:    "TCP",
		L7Protocol:  "TLS",
		Host:        "google.com",
		Packets:     10,
		Bytes:       2400,
		DurationMs:  150,
		HandshakeMs: 18,
		Details:     map[string]string{"version": "TLS 1.3"},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(ev)
	}
}

func Benchmark_JSON_ZeroAlloc_AppendJSON(b *testing.B) {
	ev := FlowEvent{
		Timestamp:   time.Now(),
		SrcIP:       "192.168.1.100",
		DstIP:       "142.250.190.46",
		SrcPort:     51234,
		DstPort:     443,
		Protocol:    "TCP",
		L7Protocol:  "TLS",
		Host:        "google.com",
		Packets:     10,
		Bytes:       2400,
		DurationMs:  150,
		HandshakeMs: 18,
		Details:     map[string]string{"version": "TLS 1.3"},
	}

	scratch := make([]byte, 0, 512)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		scratch = ev.AppendJSON(scratch[:0])
	}
}

