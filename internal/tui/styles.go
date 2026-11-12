package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Pastel Pop Color Tokens
	ColorFoxOrange = lipgloss.Color("#FF8C42") // 🦊 Fox DPI Brand
	ColorCyan      = lipgloss.Color("#8BE9FD") // TLS / HTTPS
	ColorPeach     = lipgloss.Color("#FFB86C") // HTTP
	ColorLavender  = lipgloss.Color("#BD93F9") // DNS / Active Tabs
	ColorPink      = lipgloss.Color("#FF7597") // Focus / Highlighting
	ColorGreen     = lipgloss.Color("#50FA7B") // Live / Success
	ColorYellow    = lipgloss.Color("#F1FA8C") // Warnings / Hotkeys
	ColorRed       = lipgloss.Color("#FF5555") // Threats / Errors
	ColorBorder    = lipgloss.Color("#4B5563") // Muted Slate Borders
	ColorMuted     = lipgloss.Color("#6272A4") // Timestamps / Dim Text
	ColorText      = lipgloss.Color("#F8F8F2") // High-Contrast Primary
	ColorDarkBg    = lipgloss.Color("#1E1E2E") // Pill Dark Background

	// Brand Pill
	StyleBrand = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDarkBg).
			Background(ColorFoxOrange).
			Padding(0, 1)

	// Live indicator
	StyleLive = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorGreen)

	// Muted / dim text style
	StyleMuted = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// Status Badges & Metrics
	StyleMetricPill = lipgloss.NewStyle().
			Foreground(ColorCyan)

	StyleFlowCount = lipgloss.NewStyle().
			Foreground(ColorLavender)

	StyleAlertNormal = lipgloss.NewStyle().
				Foreground(ColorGreen)

	StyleAlertTriggered = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorRed)

	// Navigation Tabs / Buttons
	StyleTabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorDarkBg).
			Background(ColorPink).
			Padding(0, 1)

	StyleTabInactive = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Padding(0, 1)

	StyleKeyHint = lipgloss.NewStyle().
			Foreground(ColorYellow)

	// Table & Containers
	StyleRoundedBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorBorder)

	StyleTableHeader = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorMuted)

	StyleRowSelected = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorText).
				Background(lipgloss.Color("#2A2C3D"))

	// Protocol Badges
	StyleBadgeTLS = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorCyan)

	StyleBadgeHTTP = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorPeach)

	StyleBadgeDNS = lipgloss.NewStyle().
			Bold(true).
			Foreground(ColorLavender)

	StyleBadgeOther = lipgloss.NewStyle().
			Foreground(ColorMuted)

	// Alert Severity Badges
	StyleSeverityHigh = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorDarkBg).
				Background(ColorRed).
				Padding(0, 1)

	StyleSeverityWarn = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorDarkBg).
				Background(ColorYellow).
				Padding(0, 1)

	StyleSeverityInfo = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorDarkBg).
				Background(ColorCyan).
				Padding(0, 1)

	// Inspector Drawer
	StyleDrawer = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(ColorLavender)

	StyleDrawerLabel = lipgloss.NewStyle().
				Foreground(ColorMuted)

	StyleDrawerValue = lipgloss.NewStyle().
				Bold(true).
				Foreground(ColorText)
)
