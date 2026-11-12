package tui

import (
	"fmt"
	"strings"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/sink"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Tab represents active view tab.
type Tab int

const (
	TabFlows Tab = iota
	TabAlerts
	TabGraphs
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type tickMsg time.Time

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*66, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Model maintains the state of the interactive Fox DPI terminal.
type Model struct {
	bridge     *EventBridge
	metricsFn  func() engine.Metrics
	ifaceDesc  string
	startTime  time.Time

	width      int
	height     int

	activeTab  Tab
	showDrawer bool
	paused     bool

	selectedIdx  int
	spinnerIdx   int
	tickCounter  int

	cachedFlows  []sink.FlowEvent
	cachedAlerts []sink.AlertEvent
	cachedStats  BridgeStats
}

// NewModel creates an initialized Bubble Tea model.
func NewModel(bridge *EventBridge, metricsFn func() engine.Metrics, ifaceDesc string) Model {
	return Model{
		bridge:      bridge,
		metricsFn:   metricsFn,
		ifaceDesc:   ifaceDesc,
		startTime:   time.Now(),
		activeTab:   TabFlows,
		cachedStats: bridge.BridgeSnapshot(0, 0, 0),
	}
}

// Init initializes the tea program loop.
func (m Model) Init() tea.Cmd {
	return tickCmd()
}

// Update processes terminal input and tick messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		m.tickCounter++
		m.spinnerIdx = (m.spinnerIdx + 1) % len(spinnerFrames)

		var totalPkts, totalBytes uint64
		var activeFlows int
		if m.metricsFn != nil {
			met := m.metricsFn()
			totalPkts = met.TotalPackets
			totalBytes = met.TotalBytes
			activeFlows = met.ActiveFlows
		}

		// Every ~1s (15 ticks of 66ms), sample throughput history
		if m.tickCounter%15 == 0 {
			m.bridge.TickSample(totalBytes)
		}

		if !m.paused {
			m.cachedFlows = m.bridge.SnapshotFlows()
			m.cachedAlerts = m.bridge.SnapshotAlerts()
			m.cachedStats = m.bridge.BridgeSnapshot(totalPkts, totalBytes, activeFlows)
		}

		return m, tickCmd()

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
			return m, nil

		case "1":
			m.activeTab = TabFlows
			return m, nil

		case "2":
			m.activeTab = TabAlerts
			return m, nil

		case "3", "g":
			if m.activeTab == TabGraphs {
				m.activeTab = TabFlows
			} else {
				m.activeTab = TabGraphs
			}
			return m, nil

		case " ":
			m.paused = !m.paused
			return m, nil

		case "enter", "i":
			if m.activeTab == TabFlows && len(m.cachedFlows) > 0 {
				m.showDrawer = !m.showDrawer
			}
			return m, nil

		case "esc":
			if m.showDrawer {
				m.showDrawer = false
				return m, nil
			}

		case "up", "k":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
			return m, nil

		case "down", "j":
			maxItems := len(m.cachedFlows)
			if m.activeTab == TabAlerts {
				maxItems = len(m.cachedAlerts)
			}
			if m.selectedIdx < maxItems-1 {
				m.selectedIdx++
			}
			return m, nil

		case "c":
			// Clear buffer
			m.cachedFlows = nil
			m.cachedAlerts = nil
			m.selectedIdx = 0
			return m, nil
		}
	}

	return m, nil
}

// View renders the entire screen.
func (m Model) View() string {
	if m.width < 50 || m.height < 12 {
		return "Terminal window too small for Fox DPI. Please enlarge."
	}

	// 1. Header
	header := m.renderHeader()

	// 2. Navigation Pills
	nav := m.renderNav()

	// 3. Main Body Viewport
	bodyHeight := m.height - 10
	if bodyHeight < 4 {
		bodyHeight = 4
	}

	var body string
	switch m.activeTab {
	case TabAlerts:
		body = m.renderAlertsView(bodyHeight)
	case TabGraphs:
		body = m.renderGraphsView(bodyHeight)
	default:
		body = m.renderFlowsView(bodyHeight)
	}

	// 4. Footer
	footer := m.renderFooter()

	return lipgloss.JoinVertical(lipgloss.Left, header, nav, body, footer)
}

func (m Model) renderHeader() string {
	brand := StyleBrand.Render("🦊 FOX DPI")

	var status string
	if m.paused {
		status = StyleSeverityWarn.Render("⏸ PAUSED")
	} else {
		status = StyleLive.Render(fmt.Sprintf("%s LIVE", spinnerFrames[m.spinnerIdx]))
	}

	secs := time.Since(m.startTime).Seconds()
	rate := uint64(0)
	if secs > 0 {
		rate = uint64(float64(m.cachedStats.TotalPackets) / secs)
	}

	rateStr := StyleMetricPill.Render(fmt.Sprintf("⚡ %s pkts/s", formatInt(rate)))
	flowsStr := StyleFlowCount.Render(fmt.Sprintf("◈ %d flows", m.cachedStats.ActiveFlows))

	var alertBadge string
	if m.cachedStats.TotalAlerts == 0 {
		alertBadge = StyleAlertNormal.Render("🛡 0 alerts")
	} else {
		alertBadge = StyleAlertTriggered.Render(fmt.Sprintf("🚨 %d ALERTS", m.cachedStats.TotalAlerts))
	}

	topRow := fmt.Sprintf("%s  %s    %s │ %s │ %s", brand, status, rateStr, flowsStr, alertBadge)

	bytesStr := formatBytes(m.cachedStats.TotalBytes)
	subRow := StyleMuted.Render(fmt.Sprintf("Capture: %s  •  Volume: %s", truncate(m.ifaceDesc, m.width-35), bytesStr))

	boxWidth := m.width - 2
	return StyleRoundedBox.Width(boxWidth).Render(topRow + "\n" + subRow)
}

func (m Model) renderNav() string {
	tab1 := StyleTabInactive.Render("[1 Flows]")
	if m.activeTab == TabFlows {
		tab1 = StyleTabActive.Render("[1 Flows]")
	}

	alertCount := m.cachedStats.TotalAlerts
	tab2Text := fmt.Sprintf("[2 Threats (%d)]", alertCount)
	tab2 := StyleTabInactive.Render(tab2Text)
	if m.activeTab == TabAlerts {
		tab2 = StyleTabActive.Render(tab2Text)
	}

	tab3 := StyleTabInactive.Render("[3 Analytics (g)]")
	if m.activeTab == TabGraphs {
		tab3 = StyleTabActive.Render("[3 Analytics (g)]")
	}

	return fmt.Sprintf(" %s %s %s", tab1, tab2, tab3)
}

func (m Model) renderFlowsView(maxRows int) string {
	boxWidth := m.width - 2

	if m.showDrawer && len(m.cachedFlows) > 0 {
		return m.renderSplitFlowView(maxRows, boxWidth)
	}

	// Full table
	headers := m.formatFlowHeader(boxWidth)
	var rows []string
	rows = append(rows, headers)

	if len(m.cachedFlows) == 0 {
		rows = append(rows, StyleMuted.Render("  Waiting for network packets..."))
	} else {
		// Clamp selection
		if m.selectedIdx >= len(m.cachedFlows) {
			m.selectedIdx = len(m.cachedFlows) - 1
		}

		displayCount := maxRows - 1
		if displayCount > len(m.cachedFlows) {
			displayCount = len(m.cachedFlows)
		}

		for i := 0; i < displayCount; i++ {
			flow := m.cachedFlows[i]
			isSelected := (i == m.selectedIdx)
			row := m.formatFlowRow(flow, isSelected, boxWidth)
			rows = append(rows, row)
		}
	}

	content := strings.Join(rows, "\n")
	return StyleRoundedBox.Width(boxWidth).Height(maxRows).Render(content)
}

func (m Model) formatFlowHeader(width int) string {
	if width < 90 {
		// Compact columns
		return StyleTableHeader.Render(fmt.Sprintf(" %-8s %-5s %-20s %-24s %-8s", "TIME", "L7", "DESTINATION", "HOST / SNI", "BYTES"))
	}
	// Full width
	return StyleTableHeader.Render(fmt.Sprintf(" %-8s %-4s %-5s %-21s %-21s %-22s %-6s %-7s",
		"TIME", "L4", "L7", "SOURCE", "DESTINATION", "HOST / SNI", "RTT", "BYTES"))
}

func (m Model) formatFlowRow(f sink.FlowEvent, isSelected bool, width int) string {
	timeStr := f.Timestamp.Format("15:04:05")
	l4 := f.Protocol
	l7 := f.L7Protocol
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

	host := f.Host
	if host == "" {
		host = "-"
	}

	rttStr := "-"
	if f.HandshakeMs > 0 {
		rttStr = fmt.Sprintf("%dms", f.HandshakeMs)
	}

	bytesStr := formatBytes(f.Bytes)
	dst := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
	src := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)

	var line string
	if width < 90 {
		line = fmt.Sprintf(" %-8s %s %-20s %-24s %-8s",
			timeStr, badge, truncate(dst, 20), truncate(host, 24), bytesStr)
	} else {
		line = fmt.Sprintf(" %-8s %-4s %s %-21s %-21s %-22s %-6s %-7s",
			timeStr, l4, badge, truncate(src, 21), truncate(dst, 21), truncate(host, 22), rttStr, bytesStr)
	}

	if isSelected {
		return StyleRowSelected.Width(width - 2).Render("▎" + line[1:])
	}
	return line
}

func (m Model) renderFooter() string {
	boxWidth := m.width - 2
	elapsed := time.Since(m.startTime).Round(time.Second)

	left := fmt.Sprintf(" %s Switch  %s Inspect  %s Pause  %s Graphs  %s Clear  %s Quit",
		StyleKeyHint.Render("[Tab]"),
		StyleKeyHint.Render("[Enter]"),
		StyleKeyHint.Render("[Space]"),
		StyleKeyHint.Render("[g]"),
		StyleKeyHint.Render("[c]"),
		StyleKeyHint.Render("[q]"),
	)

	right := StyleMuted.Render(fmt.Sprintf("%s ", elapsed))
	space := boxWidth - lipgloss.Width(left) - lipgloss.Width(right)
	if space < 1 {
		space = 1
	}

	return StyleRoundedBox.Width(boxWidth).Render(left + strings.Repeat(" ", space) + right)
}

func truncate(s string, maxLen int) string {
	if maxLen <= 3 || len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func formatInt(n uint64) string {
	in := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(in)+(len(in)-1)/3)
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(b)/float64(div), "KMGTPE"[exp])
}
