package tui

func (m Model) renderSplitFlowView(maxRows int, totalWidth int) string {
	return m.renderFlowsView(maxRows)
}

func (m Model) renderAlertsView(maxRows int) string {
	return StyleRoundedBox.Width(m.width - 2).Height(maxRows).Render("Alerts View")
}
