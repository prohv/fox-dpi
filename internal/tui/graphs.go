package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var sparkChars = []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func (m Model) renderGraphsView(maxRows int) string {
	boxWidth := m.width - 2
	var lines []string

	title := StyleBrand.Render(" 📊 TRAFFIC ANALYTICS & DISTRIBUTION ")
	lines = append(lines, title, "")

	// 1. Protocol Distribution Horizontal Bars
	totalFlows := m.cachedStats.TLSFlows + m.cachedStats.HTTPFlows + m.cachedStats.DNSFlows + m.cachedStats.OtherFlows
	lines = append(lines, StyleKeyHint.Render("─ Protocol Distribution ─────────────────────────────────"))

	renderProtoBar := func(name string, count uint64, style lipgloss.Style) string {
		pct := 0
		if totalFlows > 0 {
			pct = int((count * 100) / totalFlows)
		}
		barWidth := (boxWidth * pct) / 150 // Scaled to ~66% max
		if barWidth < 1 && count > 0 {
			barWidth = 1
		}
		if barWidth > 45 {
			barWidth = 45
		}

		bar := style.Render(strings.Repeat("█", barWidth))
		return fmt.Sprintf(" %-6s %s %s (%d%% · %s flows)",
			name, bar, strings.Repeat(" ", 45-barWidth), pct, formatInt(count))
	}

	lines = append(lines, renderProtoBar("TLS", m.cachedStats.TLSFlows, StyleBadgeTLS))
	lines = append(lines, renderProtoBar("HTTP", m.cachedStats.HTTPFlows, StyleBadgeHTTP))
	lines = append(lines, renderProtoBar("DNS", m.cachedStats.DNSFlows, StyleBadgeDNS))
	lines = append(lines, renderProtoBar("OTHER", m.cachedStats.OtherFlows, StyleBadgeOther))
	lines = append(lines, "")

	// 2. Throughput Sparkline (Rolling 30s)
	lines = append(lines, StyleKeyHint.Render("─ Live Throughput History (Rolling 30s) ─────────────────"))
	history := m.cachedStats.ThroughputHistory
	if len(history) == 0 {
		lines = append(lines, StyleMuted.Render(" Sampling network bandwidth..."))
	} else {
		maxMB := 0.01
		for _, v := range history {
			if v > maxMB {
				maxMB = v
			}
		}

		var sparkline strings.Builder
		sparkline.WriteString(" MB/s  ")
		for _, v := range history {
			idx := int((v / maxMB) * float64(len(sparkChars)-1))
			if idx < 0 {
				idx = 0
			}
			if idx >= len(sparkChars) {
				idx = len(sparkChars) - 1
			}

			ch := string(sparkChars[idx])
			if v > (maxMB * 0.75) {
				sparkline.WriteString(StyleSeverityHigh.Render(ch))
			} else if v > (maxMB * 0.4) {
				sparkline.WriteString(StyleKeyHint.Render(ch))
			} else {
				sparkline.WriteString(StyleLive.Render(ch))
			}
		}
		curMB := 0.0
		if len(history) > 0 {
			curMB = history[len(history)-1]
		}
		sparkline.WriteString(fmt.Sprintf("  (Peak: %.2f MB/s · Current: %.2f MB/s)", maxMB, curMB))
		lines = append(lines, sparkline.String())
	}
	lines = append(lines, "")

	// 3. Top Destination Hosts
	lines = append(lines, StyleKeyHint.Render("─ Top Destination Talkers ───────────────────────────────"))
	if len(m.cachedStats.TopHosts) == 0 {
		lines = append(lines, StyleMuted.Render(" No external domain telemetry aggregated yet."))
	} else {
		for i, h := range m.cachedStats.TopHosts {
			lines = append(lines, fmt.Sprintf(" %d. %-32s (%s · %d flows)",
				i+1, StyleDrawerValue.Render(truncate(h.Host, 32)), formatBytes(h.Bytes), h.Flows))
		}
	}

	lines = append(lines, "", StyleMuted.Render(" [Esc] / [1] Return to Live Flows"))

	return NewBox().Width(boxWidth).Height(maxRows).Render(strings.Join(lines, "\n"))
}
