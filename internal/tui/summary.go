package tui

import (
	"fmt"
	"strings"
	"time"

	"fox-dpi/internal/engine"

	"github.com/charmbracelet/lipgloss"
)

// RenderSummary formats a compact, rounded, pastel-pop run summary that hugs its content.
func RenderSummary(m engine.Metrics, elapsed time.Duration, outDir, captureDesc string) string {
	secs := elapsed.Seconds()
	rate := uint64(0)
	if secs > 0 {
		rate = uint64(float64(m.TotalPackets) / secs)
	}

	brand := StyleBrand.Render(" 🦊 FOX-DPI RUN SUMMARY ")
	timeStr := StyleMetricPill.Render(fmt.Sprintf("%s", elapsed.Round(time.Millisecond)))
	throughputStr := StyleLive.Render(fmt.Sprintf("⚡ %s pkts/sec", formatInt(rate)))

	topLine := fmt.Sprintf("%s • Time: %s • Rate: %s", brand, timeStr, throughputStr)
	modeLine := StyleMuted.Render(fmt.Sprintf("Capture: %s", captureDesc))
	outLine := StyleMuted.Render(fmt.Sprintf("Output:  %s/", outDir))

	const boxInnerWidth = 66
	divider := StyleBorder.Render(strings.Repeat("─", boxInnerWidth))

	// Section 1: Ingestion stats
	col1Title := StyleKeyHint.Render("PACKET INGESTION")
	col1Pkt := fmt.Sprintf("  Total Processed : %s", StyleDrawerValue.Render(formatInt(m.TotalPackets)))
	col1Vol := fmt.Sprintf("  Total Volume    : %s", StyleDrawerValue.Render(formatBytes(m.TotalBytes)))
	col1Loss := fmt.Sprintf("  Loss / Errors   : %s", StyleDrawerValue.Render(formatInt(m.DropPackets)))

	col1 := strings.Join([]string{col1Title, col1Pkt, col1Vol, col1Loss}, "\n")

	// Section 2: Flow state & threats
	col2Title := StyleKeyHint.Render("FLOWS & THREATS")
	col2Emitted := fmt.Sprintf("  Flows Recorded  : %s", StyleFlowCount.Render(formatInt(m.EmittedFlows)))
	col2Active := fmt.Sprintf("  Active at Exit  : %s", StyleFlowCount.Render(fmt.Sprintf("%d", m.ActiveFlows)))

	var col2Alerts string
	if m.EmittedAlerts == 0 {
		col2Alerts = fmt.Sprintf("  Security Alerts Fired : %s", StyleAlertNormal.Render("0 (Clean)"))
	} else {
		col2Alerts = fmt.Sprintf("  Security Alerts Fired : %s", StyleAlertTriggered.Render(fmt.Sprintf("🚨 %d FIRED", m.EmittedAlerts)))
	}

	col2 := strings.Join([]string{col2Title, col2Emitted, col2Active, col2Alerts}, "\n")

	// Side-by-side columns
	grid := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(33).Render(col1),
		lipgloss.NewStyle().Width(33).Render(col2),
	)

	content := strings.Join([]string{
		topLine,
		modeLine,
		outLine,
		divider,
		grid,
	}, "\n")

	// NewBox creates a fresh style with no lingering height settings, hugging the content
	return "\n" + NewBox().Width(boxInnerWidth+2).Render(content) + "\n"
}
