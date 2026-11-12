package tui

import (
	"strings"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/sink"

	tea "github.com/charmbracelet/bubbletea"
)

func TestEventBridge_RingBuffer_And_Aggregation(t *testing.T) {
	bridge := NewEventBridge(nil, 4, 2)

	// Emit 6 flows (exceeding capacity of 4)
	for i := 1; i <= 6; i++ {
		proto := "TLS"
		if i%2 == 0 {
			proto = "HTTP"
		}
		bridge.EmitFlow(sink.FlowEvent{
			Timestamp:  time.Now(),
			SrcIP:      "192.168.1.10",
			DstIP:      "1.1.1.1",
			L7Protocol: proto,
			Host:       "api.example.com",
			Bytes:      uint64(i * 100),
		})
	}

	flows := bridge.SnapshotFlows()
	if len(flows) != 4 {
		t.Fatalf("expected 4 flows capped in ring buffer, got %d", len(flows))
	}
	// Newest flow should be flow 6 (600 bytes)
	if flows[0].Bytes != 600 {
		t.Errorf("expected newest flow to have 600 bytes, got %d", flows[0].Bytes)
	}

	// Verify protocol distribution counters
	stats := bridge.BridgeSnapshot(10, 1000, 2)
	if stats.TLSFlows != 3 || stats.HTTPFlows != 3 {
		t.Errorf("expected 3 TLS and 3 HTTP flows, got %d TLS, %d HTTP", stats.TLSFlows, stats.HTTPFlows)
	}

	// Verify top talkers aggregation
	if len(stats.TopHosts) != 1 || stats.TopHosts[0].Host != "api.example.com" {
		t.Fatalf("expected 1 top host 'api.example.com', got %+v", stats.TopHosts)
	}
	expectedBytes := uint64(100 + 200 + 300 + 400 + 500 + 600)
	if stats.TopHosts[0].Bytes != expectedBytes {
		t.Errorf("expected %d total host bytes, got %d", expectedBytes, stats.TopHosts[0].Bytes)
	}

	// Verify Alert ring buffer
	bridge.EmitAlert(sink.AlertEvent{Rule: "RULE_1", Severity: "WARN"})
	bridge.EmitAlert(sink.AlertEvent{Rule: "RULE_2", Severity: "HIGH"})
	bridge.EmitAlert(sink.AlertEvent{Rule: "RULE_3", Severity: "HIGH"})

	alerts := bridge.SnapshotAlerts()
	if len(alerts) != 2 {
		t.Fatalf("expected 2 alerts capped in ring buffer, got %d", len(alerts))
	}
	if alerts[0].Rule != "RULE_3" {
		t.Errorf("expected newest alert to be RULE_3, got %s", alerts[0].Rule)
	}
}

func TestModel_Update_Keybindings(t *testing.T) {
	bridge := NewEventBridge(nil, 10, 10)
	bridge.EmitFlow(sink.FlowEvent{
		Timestamp:  time.Now(),
		SrcIP:      "10.0.0.1",
		DstIP:      "10.0.0.2",
		L7Protocol: "TLS",
		Host:       "test.com",
	})

	metricsFn := func() engine.Metrics {
		return engine.Metrics{TotalPackets: 50, TotalBytes: 2048, ActiveFlows: 1}
	}

	model := NewModel(bridge, metricsFn, nil, "TestInterface")

	// 1. Resize Window
	mAny, _ := model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m := mAny.(Model)
	if m.width != 100 || m.height != 30 {
		t.Errorf("expected dimensions 100x30, got %dx%d", m.width, m.height)
	}

	// 2. Tab Navigation
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = mAny.(Model)
	if m.activeTab != TabAlerts {
		t.Errorf("expected TabAlerts, got %v", m.activeTab)
	}

	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	m = mAny.(Model)
	if m.activeTab != TabGraphs {
		t.Errorf("expected TabGraphs, got %v", m.activeTab)
	}

	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m = mAny.(Model)
	if m.activeTab != TabFlows {
		t.Errorf("expected TabFlows, got %v", m.activeTab)
	}

	// 3. Pause Toggle
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeySpace})
	m = mAny.(Model)
	if !m.paused {
		t.Error("expected model to be paused after spacebar")
	}

	// 4. Drawer Toggle on Flow Table
	m.cachedFlows = bridge.SnapshotFlows()
	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = mAny.(Model)
	if !m.showDrawer {
		t.Error("expected showDrawer to be true after Enter")
	}

	mAny, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = mAny.(Model)
	if m.showDrawer {
		t.Error("expected showDrawer to be false after Esc")
	}
}

func TestModel_View_Responsiveness(t *testing.T) {
	bridge := NewEventBridge(nil, 10, 10)
	bridge.EmitFlow(sink.FlowEvent{
		Timestamp:  time.Now(),
		SrcIP:      "192.168.1.100",
		DstIP:      "93.184.216.34",
		SrcPort:    54321,
		DstPort:    443,
		Protocol:   "TCP",
		L7Protocol: "TLS",
		Host:       "example.com",
		Bytes:      1500,
	})

	m := NewModel(bridge, nil, nil, "eth0")

	// 1. Very small terminal (< 40 cols)
	m.width = 35
	m.height = 8
	view := m.View()
	if view != "Terminal window too small for Fox DPI. Please enlarge." {
		t.Errorf("expected small window warning, got %q", view)
	}

	// 2. Narrow terminal (80 cols)
	m.width = 80
	m.height = 24
	m.cachedFlows = bridge.SnapshotFlows()
	m.cachedStats = bridge.BridgeSnapshot(1, 1500, 1)
	view = m.View()
	if len(view) == 0 {
		t.Error("expected non-empty view in narrow mode")
	}

	// 3. Wide terminal (120 cols) with split drawer
	m.width = 120
	m.height = 30
	m.showDrawer = false
	header := m.renderHeader()
	nav := m.renderNav()
	body := m.renderFlowsView(m.height - 11)
	footer := m.renderFooter()
	t.Logf("header lines: %d", len(strings.Split(header, "\n")))
	t.Logf("nav lines: %d", len(strings.Split(nav, "\n")))
	t.Logf("body lines: %d", len(strings.Split(body, "\n")))
	t.Logf("footer lines: %d", len(strings.Split(footer, "\n")))
	view = m.View()
	lines := strings.Split(view, "\n")
	t.Logf("m.height=30, rendered line count=%d", len(lines))
	if len(lines) > m.height {
		t.Errorf("rendered line count %d exceeds terminal height %d! View will scroll off screen!", len(lines), m.height)
	}

	// 4. Graphs view
	m.activeTab = TabGraphs
	view = m.View()
	if len(view) == 0 {
		t.Error("expected non-empty view in graphs mode")
	}
}

func TestRenderSummary_Compact(t *testing.T) {
	met := engine.Metrics{
		TotalPackets:  45,
		TotalBytes:    6500,
		DropPackets:   0,
		EmittedFlows:  1,
		ActiveFlows:   0,
		EmittedAlerts: 0,
	}

	summary := RenderSummary(met, 13700*time.Millisecond, "output", "Live Capture on Wi-Fi (172.16.70.229)")
	lines := strings.Split(strings.TrimSpace(summary), "\n")
	t.Logf("Summary rendered %d lines:\n%s", len(lines), summary)

	// Summary should be compact (around 10-12 lines total, not 25-30!)
	if len(lines) > 15 {
		t.Errorf("summary is too tall (%d lines), should be compact <= 15 lines!", len(lines))
	}
}
