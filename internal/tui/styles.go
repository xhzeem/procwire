package tui

import "github.com/charmbracelet/lipgloss"

type styles struct {
	normal        lipgloss.Style
	muted         lipgloss.Style
	faint         lipgloss.Style
	accent        lipgloss.Style
	success       lipgloss.Style
	warning       lipgloss.Style
	danger        lipgloss.Style
	local         lipgloss.Style
	generated     lipgloss.Style
	brand         lipgloss.Style
	tab           lipgloss.Style
	activeTab     lipgloss.Style
	tableHeader   lipgloss.Style
	tableCell     lipgloss.Style
	tableSelected lipgloss.Style
	panel         lipgloss.Style
	label         lipgloss.Style
	value         lipgloss.Style
}

func newStyles() styles {
	text := lipgloss.AdaptiveColor{Light: "#20262E", Dark: "#D8DEE9"}
	muted := lipgloss.AdaptiveColor{Light: "#657180", Dark: "#788493"}
	faint := lipgloss.AdaptiveColor{Light: "#A2AAB5", Dark: "#46515F"}
	accent := lipgloss.AdaptiveColor{Light: "#087E8B", Dark: "#5FD7D7"}
	green := lipgloss.AdaptiveColor{Light: "#287A3D", Dark: "#87D787"}
	amber := lipgloss.AdaptiveColor{Light: "#9A5B00", Dark: "#FFAF5F"}
	red := lipgloss.AdaptiveColor{Light: "#B3261E", Dark: "#FF6B6B"}
	magenta := lipgloss.AdaptiveColor{Light: "#8A3FA0", Dark: "#D787FF"}
	blue := lipgloss.AdaptiveColor{Light: "#3167A5", Dark: "#75AFFF"}
	selected := lipgloss.AdaptiveColor{Light: "#D8EEF0", Dark: "#17363B"}
	border := lipgloss.AdaptiveColor{Light: "#CBD2D9", Dark: "#36414F"}

	return styles{
		normal:        lipgloss.NewStyle().Foreground(text),
		muted:         lipgloss.NewStyle().Foreground(muted),
		faint:         lipgloss.NewStyle().Foreground(faint),
		accent:        lipgloss.NewStyle().Foreground(accent),
		success:       lipgloss.NewStyle().Foreground(green),
		warning:       lipgloss.NewStyle().Foreground(amber),
		danger:        lipgloss.NewStyle().Foreground(red),
		local:         lipgloss.NewStyle().Foreground(magenta),
		generated:     lipgloss.NewStyle().Foreground(blue),
		brand:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#081014"}).Background(accent).Padding(0, 1),
		tab:           lipgloss.NewStyle().Foreground(muted).Padding(0, 1),
		activeTab:     lipgloss.NewStyle().Bold(true).Foreground(accent).Background(selected).Padding(0, 1),
		tableHeader:   lipgloss.NewStyle().Bold(true).Foreground(muted).BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(border),
		tableCell:     lipgloss.NewStyle().Foreground(text),
		tableSelected: lipgloss.NewStyle().Bold(true).Foreground(text).Background(selected),
		panel:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1),
		label:         lipgloss.NewStyle().Bold(true).Foreground(muted).Width(17),
		value:         lipgloss.NewStyle().Foreground(text),
	}
}

func (s styles) provenance(value string) lipgloss.Style {
	switch value {
	case "package-match":
		return s.success
	case "package-modified":
		return s.warning.Bold(true)
	case "package-owned":
		return s.generated
	case "local":
		return s.local
	case "generated":
		return s.generated
	default:
		return s.muted
	}
}
