package tui

func (m Model) renderGraphsView(maxRows int) string {
	return StyleRoundedBox.Width(m.width - 2).Height(maxRows).Render("Graphs View")
}
