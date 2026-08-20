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
	alt           lipgloss.Style
	brand         lipgloss.Style
	tab           lipgloss.Style
	activeTab     lipgloss.Style
	tableHeader   lipgloss.Style
	tableCell     lipgloss.Style
	tableSelected lipgloss.Style
	selectedFill  lipgloss.TerminalColor
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
	olive := lipgloss.AdaptiveColor{Light: "#6F5B00", Dark: "#D7C87A"}
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
		alt:           lipgloss.NewStyle().Foreground(olive),
		brand:         lipgloss.NewStyle().Bold(true).Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#081014"}).Background(accent).Padding(0, 1),
		tab:           lipgloss.NewStyle().Foreground(muted).Padding(0, 1),
		activeTab:     lipgloss.NewStyle().Bold(true).Foreground(accent).Background(selected).Padding(0, 1),
		tableHeader:   lipgloss.NewStyle().Bold(true).Foreground(muted).BorderBottom(true).BorderStyle(lipgloss.NormalBorder()).BorderForeground(border),
		tableCell:     lipgloss.NewStyle().Foreground(text),
		tableSelected: lipgloss.NewStyle().Bold(true).Foreground(text).Background(selected),
		selectedFill:  selected,
		panel:         lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(border).Padding(0, 1),
		label:         lipgloss.NewStyle().Bold(true).Foreground(muted).Width(17),
		value:         lipgloss.NewStyle().Foreground(text),
	}
}

// trust gives every integrity label its own colour so a row's verdict reads
// before its text does. The labels are the ones provenanceLabel produces plus
// the two process-only states, KERNEL and PENDING.
func (s styles) trust(label string) lipgloss.Style {
	switch label {
	case "SYSTEM":
		return s.success
	case "MODIFIED":
		return s.danger.Bold(true)
	case "OWNED":
		return s.warning
	case "LOCAL":
		return s.local
	case "GENERATED":
		return s.generated
	case "PENDING":
		return s.accent
	case "KERNEL":
		return s.faint
	default:
		return s.muted
	}
}

func (s styles) provenance(value string) lipgloss.Style {
	switch value {
	case "package-match":
		return s.trust("SYSTEM")
	case "package-modified":
		return s.trust("MODIFIED")
	case "package-owned":
		return s.trust("OWNED")
	case "local":
		return s.trust("LOCAL")
	case "generated":
		return s.trust("GENERATED")
	default:
		return s.trust("UNKNOWN")
	}
}

// risk colours the triage score as a five-step ramp, so scanning the column
// is enough to find where to start.
func (s styles) risk(score int) lipgloss.Style {
	switch {
	case score >= riskCritical:
		return s.danger.Bold(true)
	case score >= riskWarning:
		return s.danger
	case score >= riskElevated:
		return s.warning
	case score >= riskReview:
		return s.generated
	default:
		return s.faint
	}
}

// user gives each account a stable colour of its own, so a process running as
// an account its siblings do not use stands out in the column. root is pinned
// rather than hashed because it is the account that matters most.
func (s styles) user(name string) lipgloss.Style {
	switch name {
	case "":
		return s.faint
	case "root", "0":
		return s.warning.Bold(true)
	}
	palette := []lipgloss.Style{s.success, s.generated, s.local, s.accent, s.normal, s.alt}
	hash := uint32(2166136261)
	for _, char := range []byte(name) {
		hash = (hash ^ uint32(char)) * 16777619
	}
	return palette[hash%uint32(len(palette))]
}
