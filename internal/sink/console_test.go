package sink

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type mockSink struct {
	flowCount  int
	alertCount int
	closed     bool
}

func (m *mockSink) EmitFlow(event FlowEvent) {
	m.flowCount++
}

func (m *mockSink) EmitAlert(event AlertEvent) {
	m.alertCount++
}

func (m *mockSink) Stats() Stats {
	return Stats{
		EmittedFlows:  uint64(m.flowCount),
		EmittedAlerts: uint64(m.alertCount),
	}
}

func (m *mockSink) Close() error {
	m.closed = true
	return nil
}

func TestConsoleAlertSink_LiveAlerts(t *testing.T) {
	mock := &mockSink{}
	consoleSink := NewConsoleAlertSink(mock, true)

	// Intercept stderr
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stderr = w

	alert := AlertEvent{
		Timestamp: time.Now(),
		Rule:      "SUSPICIOUS_HIGH_PORT_TLS",
		Severity:  "HIGH",
		SrcIP:     "192.168.1.50",
		DstIP:     "1.1.1.1",
		SrcPort:   54321,
		DstPort:   8443,
		Protocol:  "TLS",
		Message:   "TLS handshake observed on non-standard port",
	}

	consoleSink.EmitAlert(alert)
	consoleSink.EmitFlow(FlowEvent{})

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	os.Stderr = oldStderr

	if mock.alertCount != 1 {
		t.Errorf("expected 1 alert, got %d", mock.alertCount)
	}
	if mock.flowCount != 1 {
		t.Errorf("expected 1 flow, got %d", mock.flowCount)
	}

	out := buf.String()
	if !strings.Contains(out, "[ALERT]") {
		t.Errorf("expected output to contain [ALERT], got: %s", out)
	}
	if !strings.Contains(out, "SUSPICIOUS_HIGH_PORT_TLS") {
		t.Errorf("expected output to contain SUSPICIOUS_HIGH_PORT_TLS, got: %s", out)
	}
	if !strings.Contains(out, "192.168.1.50:54321 -> 1.1.1.1:8443") {
		t.Errorf("expected output to contain endpoints, got: %s", out)
	}

	if stats := consoleSink.Stats(); stats.EmittedAlerts != 1 {
		t.Errorf("expected 1 emitted alert in stats, got %d", stats.EmittedAlerts)
	}

	if err := consoleSink.Close(); err != nil {
		t.Errorf("unexpected close error: %v", err)
	}
	if !mock.closed {
		t.Errorf("expected underlying sink to be closed")
	}
}

func TestConsoleAlertSink_NonLiveSuppressed(t *testing.T) {
	mock := &mockSink{}
	consoleSink := NewConsoleAlertSink(mock, false)

	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() failed: %v", err)
	}
	os.Stderr = w

	alert := AlertEvent{
		Rule:     "HTTP_DUPLICATE_HOST",
		Severity: "MEDIUM",
	}

	consoleSink.EmitAlert(alert)

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	_ = r.Close()
	os.Stderr = oldStderr

	if mock.alertCount != 1 {
		t.Errorf("expected 1 alert, got %d", mock.alertCount)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Errorf("expected no stderr output in non-live mode, got: %s", buf.String())
	}
}
