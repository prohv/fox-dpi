package tui

import (
	"fmt"
	"strings"

	"fox-dpi/internal/sink"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) renderSplitFlowView(maxRows int, totalWidth int) string {
	leftWidth := (totalWidth * 6) / 10
	rightWidth := totalWidth - leftWidth - 2
	if leftWidth < 30 || rightWidth < 25 {
		// Terminal too narrow for split view, fall back to full table
		return m.renderFlowsView(maxRows)
	}

	// 1. Left compact table
	header := StyleTableHeader.Render(fmt.Sprintf(" %-8s %-5s %-16s %-18s", "TIME", "L7", "DESTINATION", "HOST"))
	var leftRows []string
	leftRows = append(leftRows, header)

	visibleRows := maxRows - 1
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.adjustScroll(visibleRows)

	start := m.scrollOffset
	if start > len(m.cachedFlows) {
		start = 0
	}
	end := start + visibleRows
	if end > len(m.cachedFlows) {
		end = len(m.cachedFlows)
	}

	for i := start; i < end; i++ {
		flow := m.cachedFlows[i]
		isSelected := (i == m.selectedIdx)

		timeStr := flow.Timestamp.Format("15:04:05")
		l7 := flow.L7Protocol
		if l7 == "" {
			l7 = "-"
		}
		badge := StyleBadgeOther.Render(fmt.Sprintf("%-5s", l7))
		switch l7 {
		case "TLS":
			badge = StyleBadgeTLS.Render(fmt.Sprintf("%-5s", l7))
		case "HTTP":
			badge = StyleBadgeHTTP.Render(fmt.Sprintf("%-5s", l7))
		case "DNS":
			badge = StyleBadgeDNS.Render(fmt.Sprintf("%-5s", l7))
		}

		dst := fmt.Sprintf("%s:%d", flow.DstIP, flow.DstPort)
		host := flow.Host
		if host == "" {
			host = "-"
		}

		line := fmt.Sprintf(" %-8s %s %-16s %-18s", timeStr, badge, truncate(dst, 16), truncate(host, 18))
		if isSelected {
			line = StyleRowSelected.Width(leftWidth - 2).Render("▎" + line[1:])
		}
		leftRows = append(leftRows, line)
	}

	leftBox := NewBox().Width(leftWidth).Height(maxRows).Render(strings.Join(leftRows, "\n"))

	// 2. Right detail card
	var rightContent string
	if m.selectedIdx < len(m.cachedFlows) {
		selected := m.cachedFlows[m.selectedIdx]
		rightContent = m.formatFlowDetails(selected, rightWidth-2)
	} else {
		rightContent = StyleMuted.Render("No flow selected")
	}

	rightBox := NewDrawerBox().Width(rightWidth).Height(maxRows).Render(rightContent)

	return lipgloss.JoinHorizontal(lipgloss.Top, leftBox, rightBox)
}

func (m Model) formatFlowDetails(f sink.FlowEvent, width int) string {
	var lines []string

	title := StyleBrand.Render(" 🔍 FLOW INSPECTION ")
	lines = append(lines, title, "")

	appendField := func(label, val string) {
		l := StyleDrawerLabel.Render(fmt.Sprintf("%-12s: ", label))
		v := StyleDrawerValue.Render(truncate(val, width-16))
		lines = append(lines, l+v)
	}

	appendField("Protocol", fmt.Sprintf("%s / %s", f.Protocol, f.L7Protocol))
	appendField("Source", fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort))
	appendField("Destination", fmt.Sprintf("%s:%d", f.DstIP, f.DstPort))

	if f.Host != "" {
		appendField("Host / SNI", f.Host)
	}
	if f.HandshakeMs > 0 {
		appendField("TCP 3WHS RTT", fmt.Sprintf("%d ms", f.HandshakeMs))
	}

	appendField("Packets", fmt.Sprintf("%d pkts", f.Packets))
	appendField("Volume", formatBytes(f.Bytes))
	appendField("Duration", fmt.Sprintf("%d ms", f.DurationMs))

	// L7 Specific metadata details
	if len(f.Details) > 0 {
		lines = append(lines, "", StyleKeyHint.Render("─ L7 Metadata ────────────────"))
		for k, v := range f.Details {
			appendField(k, v)
		}
	}

	lines = append(lines, "", StyleMuted.Render("[Esc] Close Drawer"))

	return strings.Join(lines, "\n")
}

func (m Model) renderAlertsView(maxRows int) string {
	boxWidth := m.width - 2
	var rows []string

	header := StyleTableHeader.Render(fmt.Sprintf(" %-8s %-8s %-28s %-32s %s", "TIME", "SEVERITY", "RULE", "ENDPOINTS", "MESSAGE"))
	rows = append(rows, header)

	if len(m.cachedAlerts) == 0 {
		rows = append(rows, "", StyleAlertNormal.Render("  🛡 Clean Network Radar: Zero security anomalies or exfiltration detected."))
	} else {
		visibleRows := maxRows - 1
		if visibleRows < 1 {
			visibleRows = 1
		}
		m.adjustScroll(visibleRows)

		start := m.scrollOffset
		if start > len(m.cachedAlerts) {
			start = 0
		}
		end := start + visibleRows
		if end > len(m.cachedAlerts) {
			end = len(m.cachedAlerts)
		}

		for i := start; i < end; i++ {
			alert := m.cachedAlerts[i]
			timeStr := alert.Timestamp.Format("15:04:05")

			var sevBadge string
			switch alert.Severity {
			case "HIGH":
				sevBadge = StyleSeverityHigh.Render("HIGH")
			case "WARN":
				sevBadge = StyleSeverityWarn.Render("WARN")
			default:
				sevBadge = StyleSeverityInfo.Render("INFO")
			}

			endpoints := fmt.Sprintf("%s:%d -> %s:%d", alert.SrcIP, alert.SrcPort, alert.DstIP, alert.DstPort)
			line := fmt.Sprintf(" %-8s %-8s %-28s %-32s %s",
				timeStr, sevBadge, truncate(alert.Rule, 28), truncate(endpoints, 32), truncate(alert.Message, boxWidth-80))

			if i == m.selectedIdx {
				line = StyleRowSelected.Width(boxWidth - 2).Render("▎" + line[1:])
			}
			rows = append(rows, line)
		}
	}

	return NewBox().Width(boxWidth).Height(maxRows).Render(strings.Join(rows, "\n"))
}
