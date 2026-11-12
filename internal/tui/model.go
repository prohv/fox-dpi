package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/sink"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
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
	bridge      *EventBridge
	metricsFn   func() engine.Metrics
	liveFlowsFn func(int) []sink.FlowEvent
	ifaceDesc   string
	startTime   time.Time

	width  int
	height int

	activeTab  Tab
	showDrawer bool
	paused     bool

	selectedIdx  int
	scrollOffset int
	spinnerIdx   int
	tickCounter  int

	cachedFlows  []sink.FlowEvent
	cachedAlerts []sink.AlertEvent
	cachedStats  BridgeStats
}

// NewModel creates an initialized Bubble Tea model.
func NewModel(bridge *EventBridge, metricsFn func() engine.Metrics, liveFlowsFn func(int) []sink.FlowEvent, ifaceDesc string) Model {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 50 || h < 12 {
		w = 120
		h = 30
	}

	return Model{
		bridge:       bridge,
		metricsFn:    metricsFn,
		liveFlowsFn:  liveFlowsFn,
		ifaceDesc:    ifaceDesc,
		startTime:    time.Now(),
		activeTab:    TabFlows,
		width:        w,
		height:       h,
		cachedStats:  bridge.BridgeSnapshot(0, 0, 0),
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
		if msg.Width > 0 && msg.Height > 0 {
			m.width = msg.Width
			m.height = msg.Height
		}
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
			var live []sink.FlowEvent
			if m.liveFlowsFn != nil {
				live = m.liveFlowsFn(128)
			}
			evicted := m.bridge.SnapshotFlows()

			// Merge active and closed flows (live first)
			combined := make([]sink.FlowEvent, 0, len(live)+len(evicted))
			combined = append(combined, live...)
			// Append evicted if not exceeding 256
			for _, ef := range evicted {
				if len(combined) >= 256 {
					break
				}
				combined = append(combined, ef)
			}

			m.cachedFlows = combined
			m.cachedAlerts = m.bridge.SnapshotAlerts()
			m.cachedStats = m.bridge.BridgeSnapshot(totalPkts, totalBytes, activeFlows)
		}

		return m, tickCmd()

	case tea.MouseMsg:
		switch msg.Type {
		case tea.MouseWheelUp:
			m.moveSelection(-2)
		case tea.MouseWheelDown:
			m.moveSelection(2)
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit

		case "tab":
			m.activeTab = (m.activeTab + 1) % 3
			m.selectedIdx = 0
			m.scrollOffset = 0
			return m, nil

		case "1":
			m.activeTab = TabFlows
			m.selectedIdx = 0
			m.scrollOffset = 0
			return m, nil

		case "2":
			m.activeTab = TabAlerts
			m.selectedIdx = 0
			m.scrollOffset = 0
			return m, nil

		case "3", "g":
			if m.activeTab == TabGraphs {
				m.activeTab = TabFlows
			} else {
				m.activeTab = TabGraphs
			}
			m.selectedIdx = 0
			m.scrollOffset = 0
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
			m.moveSelection(-1)
			return m, nil

		case "down", "j":
			m.moveSelection(1)
			return m, nil

		case "pgup", "ctrl+u":
			m.moveSelection(-5)
			return m, nil

		case "pgdown", "ctrl+d":
			m.moveSelection(5)
			return m, nil

		case "home":
			m.selectedIdx = 0
			m.scrollOffset = 0
			return m, nil

		case "end":
			maxItems := m.itemCount()
			if maxItems > 0 {
				m.selectedIdx = maxItems - 1
			}
			return m, nil

		case "c":
			m.cachedFlows = nil
			m.cachedAlerts = nil
			m.selectedIdx = 0
			m.scrollOffset = 0
			return m, nil
		}
	}

	return m, nil
}

func (m *Model) itemCount() int {
	if m.activeTab == TabAlerts {
		return len(m.cachedAlerts)
	}
	return len(m.cachedFlows)
}

func (m *Model) moveSelection(delta int) {
	maxItems := m.itemCount()
	if maxItems == 0 {
		m.selectedIdx = 0
		m.scrollOffset = 0
		return
	}

	m.selectedIdx += delta
	if m.selectedIdx < 0 {
		m.selectedIdx = 0
	}
	if m.selectedIdx >= maxItems {
		m.selectedIdx = maxItems - 1
	}
}

// View renders the entire screen.
func (m Model) View() string {
	if m.width < 40 || m.height < 10 {
		return "Terminal window too small for Fox DPI. Please enlarge."
	}

	// 1. Header (4 lines total with borders)
	header := m.renderHeader()

	// 2. Navigation Pills (1 line)
	nav := m.renderNav()

	// 3. Body Viewport
	// Exact height budgeting: m.height - 4(header) - 1(nav) - 3(footer) - 2(body border) - 1(margin) = m.height - 11
	bodyContentHeight := m.height - 11
	if bodyContentHeight < 3 {
		bodyContentHeight = 3
	}

	var body string
	switch m.activeTab {
	case TabAlerts:
		body = m.renderAlertsView(bodyContentHeight)
	case TabGraphs:
		body = m.renderGraphsView(bodyContentHeight)
	default:
		body = m.renderFlowsView(bodyContentHeight)
	}

	// 4. Footer (3 lines total with borders)
	footer := m.renderFooter()

	return lipgloss.JoinVertical(lipgloss.Left, header, nav, body, footer)
}

func (m Model) renderHeader() string {
	boxWidth := m.width - 2
	if boxWidth < 40 {
		boxWidth = 40
	}

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
	topRow = truncate(topRow, boxWidth-4)

	bytesStr := formatBytes(m.cachedStats.TotalBytes)
	subRow := StyleMuted.Render(fmt.Sprintf("Capture: %s  •  Volume: %s", truncate(m.ifaceDesc, boxWidth-30), bytesStr))
	subRow = truncate(subRow, boxWidth-4)

	return NewBox().Width(boxWidth).Render(topRow + "\n" + subRow)
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

func (m *Model) adjustScroll(visibleRows int) {
	if visibleRows <= 0 {
		return
	}
	if m.selectedIdx < m.scrollOffset {
		m.scrollOffset = m.selectedIdx
	}
	if m.selectedIdx >= m.scrollOffset+visibleRows {
		m.scrollOffset = m.selectedIdx - visibleRows + 1
	}
	if m.scrollOffset < 0 {
		m.scrollOffset = 0
	}
}

func (m Model) renderFlowsView(maxRows int) string {
	boxWidth := m.width - 2
	if boxWidth < 40 {
		boxWidth = 40
	}

	if m.showDrawer && len(m.cachedFlows) > 0 {
		return m.renderSplitFlowView(maxRows, boxWidth)
	}

	visibleRows := maxRows - 1
	if visibleRows < 1 {
		visibleRows = 1
	}
	m.adjustScroll(visibleRows)

	headers := m.formatFlowHeader(boxWidth)
	var rows []string
	rows = append(rows, headers)

	if len(m.cachedFlows) == 0 {
		rows = append(rows, StyleMuted.Render("  Waiting for network packets on adapter..."))
	} else {
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
			row := m.formatFlowRow(flow, isSelected, boxWidth)
			rows = append(rows, row)
		}
	}

	content := strings.Join(rows, "\n")
	return NewBox().Width(boxWidth).Height(maxRows).Render(content)
}

func (m Model) formatFlowHeader(width int) string {
	if width < 90 {
		return StyleTableHeader.Render(fmt.Sprintf(" %-8s %-5s %-20s %-24s %-8s", "TIME", "L7", "DESTINATION", "HOST / SNI", "BYTES"))
	}
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
	if boxWidth < 40 {
		boxWidth = 40
	}
	elapsed := time.Since(m.startTime).Round(time.Second)

	var left string
	if boxWidth < 85 {
		left = fmt.Sprintf(" %s Tab  %s Enter  %s Space  %s Quit",
			StyleKeyHint.Render("[1-3]"),
			StyleKeyHint.Render("[i]"),
			StyleKeyHint.Render("[p]"),
			StyleKeyHint.Render("[q]"),
		)
	} else {
		left = fmt.Sprintf(" %s Switch  %s Inspect  %s Pause  %s Graphs  %s Clear  %s Quit",
			StyleKeyHint.Render("[Tab]"),
			StyleKeyHint.Render("[Enter]"),
			StyleKeyHint.Render("[Space]"),
			StyleKeyHint.Render("[g]"),
			StyleKeyHint.Render("[c]"),
			StyleKeyHint.Render("[q]"),
		)
	}

	right := StyleMuted.Render(fmt.Sprintf("%s ", elapsed))
	space := boxWidth - lipgloss.Width(left) - lipgloss.Width(right)
	if space < 1 {
		left = truncate(left, boxWidth-lipgloss.Width(right)-2)
		space = 1
	}

	line := left + strings.Repeat(" ", space) + right
	return NewBox().Width(boxWidth).Render(truncate(line, boxWidth-2))
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
