package tui

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/flow"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
)

type findingItem struct {
	persistence.Finding
}

func (item findingItem) FilterValue() string {
	finding := item.Finding
	values := []string{
		finding.Name,
		finding.Unit,
		finding.Mechanism,
		finding.Path,
		finding.ResolvedPath,
		finding.User,
		finding.Command,
		finding.Schedule,
		finding.Source,
		finding.Role,
		string(finding.Provenance),
		finding.Package,
		finding.Reason,
	}
	for _, evidence := range finding.ReferencedFiles {
		values = append(values, evidence.Path, evidence.Package, evidence.Integrity, string(evidence.Provenance))
	}
	return strings.Join(values, " ")
}

type findingDelegate struct {
	styles styles
}

func (findingDelegate) Height() int  { return 2 }
func (findingDelegate) Spacing() int { return 0 }

func (findingDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }

func (delegate findingDelegate) Render(writer io.Writer, model list.Model, index int, item list.Item) {
	finding, ok := item.(findingItem)
	if !ok {
		return
	}
	selected := model.Index() == index
	prefix := "  "
	if selected {
		prefix = "> "
	}
	badgeText := provenanceLabel(finding.Provenance)
	badge := delegate.styles.provenance(string(finding.Provenance)).Bold(true).Render("[" + badgeText + "]")
	name := finding.Unit
	if name == "" {
		name = finding.Name
	}
	name = sanitizeTerminal(name, false)
	meta := sanitizeTerminal(strings.TrimSpace(strings.Join([]string{finding.Mechanism, finding.Role, finding.User}, "  ")), false)
	if model.Width() < 70 {
		meta = finding.Mechanism
	}
	available := max(8, model.Width()-len(prefix)-len(badgeText)-len(meta)-8)
	lineOne := prefix + badge + " " + delegate.styles.normal.Bold(selected).Render(truncatePlain(name, available))
	if meta != "" {
		lineOne += "  " + delegate.styles.muted.Render(meta)
	}
	packageText := sanitizeTerminal(finding.Path, false)
	if finding.Package != "" {
		packageText = sanitizeTerminal(finding.PackageManager+":"+finding.Package+"  "+finding.Path, false)
	}
	lineTwo := "  " + delegate.styles.faint.Render(truncatePlain(packageText, max(8, model.Width()-2)))
	if selected {
		background := delegate.styles.tableSelected.Width(max(1, model.Width()))
		fmt.Fprint(writer, background.Render(lineOne)+"\n"+background.Render(lineTwo))
		return
	}
	fmt.Fprint(writer, lineOne+"\n"+lineTwo)
}

func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return ""
	}
	width := m.contentWidth()
	header := m.headerView()
	body := m.bodyView()
	footer := m.footerView()
	view := lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
	return lipgloss.NewStyle().MarginLeft(1).Width(width).Render(view)
}

func (m Model) headerView() string {
	width := m.contentWidth()
	left := m.styles.brand.Render("PROCWIRE")
	if width >= 100 {
		left += " " + m.styles.muted.Render("network-first Linux visibility")
		if m.version != "" {
			left += " " + m.styles.faint.Render(sanitizeTerminal(m.version, false))
		}
	}
	state := m.styles.accent.Render("STARTING")
	switch {
	case m.paused:
		state = m.styles.warning.Bold(true).Render("PAUSED VIEW")
	case m.collectorErr != nil && (isNetworkTab(m.activeTab) || m.activeTab == portsTab):
		state = m.styles.danger.Bold(true).Render("DEGRADED")
	case m.dnsErr != nil && m.activeTab == dnsTab:
		state = m.styles.warning.Bold(true).Render("DNS DEGRADED")
	case !m.lastSnapshot.IsZero() || !m.lastDNS.IsZero():
		switch {
		case isNetworkTab(m.activeTab):
			direction := "OUTBOUND"
			if m.activeTab == inboundTab {
				direction = "INBOUND"
			}
			mode := "LIVE"
			style := m.styles.accent
			if m.networkMode == sessionMode {
				mode = "SESSION"
				style = m.styles.success
			}
			state = style.Bold(true).Render(direction + " " + mode)
		case m.activeTab == dnsTab && m.dnsMode == currentDNSMode:
			state = m.styles.accent.Bold(true).Render("DNS CURRENT")
		case m.activeTab == dnsTab:
			state = m.styles.success.Bold(true).Render("DNS HISTORY")
		default:
			state = m.styles.success.Bold(true).Render("MONITORING")
		}
	}
	recording := m.styles.muted.Render("not recording")
	if m.report != "" {
		recording = m.styles.danger.Bold(true).Render("REC") + " " + m.styles.muted.Render(sanitizeTerminal(filepath.Base(m.report), false))
	}
	top := alignSides(left, state+"  "+recording, width)

	titles := []string{"1 INBOUND", "2 OUTBOUND", "3 DNS", "4 OPEN PORTS", "5 PERSISTENCE", "6 INTEGRITY"}
	if width < 80 {
		titles = []string{"1I", "2O", "3D", "4P", "5P", "6V"}
	} else if width < 105 {
		titles = []string{"1 IN", "2 OUT", "3 DNS", "4 PORTS", "5 PERSIST", "6 VERIFY"}
	}
	tabs := lipgloss.JoinHorizontal(lipgloss.Top,
		m.renderTab(inboundTab, titles[0], m.networkCountFor(inboundTab)),
		m.renderTab(outboundTab, titles[1], m.networkCountFor(outboundTab)),
		m.renderTab(dnsTab, titles[2], m.dnsCount()),
		m.renderTab(portsTab, titles[3], len(m.portFlows)),
		m.renderTab(persistenceTab, titles[4], len(m.findings)),
		m.renderTab(integrityTab, titles[5], len(m.integrityFindings)),
	)

	statsLine := m.statsLine()

	status := m.statusLine(width)
	lines := []string{top, tabs, statsLine, status}
	if m.filtering {
		lines = append(lines, m.filter.View())
	} else if m.activeTab != persistenceTab && m.activeTab != integrityTab && m.filter.Value() != "" {
		lines = append(lines, m.styles.accent.Render("Filter: ")+m.styles.normal.Render(m.filter.Value())+m.styles.muted.Render("  c clears"))
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) statsLine() string {
	if m.activeTab == dnsTab {
		mode := m.styles.success.Bold(true).Render("HISTORY")
		if m.dnsMode == historyDNSMode {
			stats := statsForDNSEvents(m.dnsHistory)
			if m.contentWidth() < 90 {
				return lipgloss.JoinHorizontal(lipgloss.Top,
					m.styles.muted.Render("VIEW "), m.styles.success.Bold(true).Render("HST"), "   ",
					m.metric("EV", m.dnsHistory.len(), m.styles.success),
					m.metric("Q", stats.queries, m.styles.accent),
					m.metric("R", stats.responses, m.styles.generated),
				)
			}
			return lipgloss.JoinHorizontal(lipgloss.Top,
				m.styles.muted.Render("VIEW "), mode, "   ",
				m.metric("EVENTS", m.dnsHistory.len(), m.styles.success),
				m.metric("QUERIES", stats.queries, m.styles.accent),
				m.metric("RESPONSES", stats.responses, m.styles.generated),
				m.metric("NAMES", len(m.baseDNS), m.styles.accent),
			)
		}
		stats := statsForDNS(m.baseDNS)
		mode = m.styles.accent.Bold(true).Render("CURRENT")
		if m.contentWidth() < 90 {
			return lipgloss.JoinHorizontal(lipgloss.Top,
				m.styles.muted.Render("VIEW "), m.styles.accent.Bold(true).Render("CUR"), "   ",
				m.metric("CACHE", stats.cached, m.styles.success),
				m.metric("OBS", len(m.baseDNS), m.styles.generated),
			)
		}
		return lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.muted.Render("VIEW "), mode, "   ",
			m.metric("RECORDS", stats.cached, m.styles.success),
			m.metric("OBSERVED", len(m.baseDNS), m.styles.generated),
			m.metric("QUERIES", stats.queries, m.styles.accent),
			m.metric("RESPONSES", stats.responses, m.styles.generated),
		)
	}
	if isNetworkTab(m.activeTab) {
		direction := "OUTBOUND"
		if m.activeTab == inboundTab {
			direction = "INBOUND"
		}
		mode := m.styles.success.Bold(true).Render("SESSION")
		if m.networkMode == liveMode {
			mode = m.styles.accent.Bold(true).Render("LIVE")
		}
		tcp, udp, unknown := 0, 0, 0
		for _, item := range m.networkFlows {
			switch {
			case strings.HasPrefix(item.Connection.Network, "tcp"):
				tcp++
			case strings.HasPrefix(item.Connection.Network, "udp"):
				udp++
			}
			if item.Connection.Direction == observe.DirectionUnknown {
				unknown++
			}
		}
		if m.contentWidth() < 90 {
			return lipgloss.JoinHorizontal(lipgloss.Top,
				m.styles.muted.Render("DIR "), m.styles.accent.Bold(true).Render(direction[:3]), "   ",
				m.styles.muted.Render("MODE "), mode, "   ",
				m.metric("ACTIVE", len(m.networkFlows), m.styles.accent),
				m.metric("SESS", len(m.networkTraffic), m.styles.success),
			)
		}
		line := lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.muted.Render("DIRECTION "), m.styles.accent.Bold(true).Render(direction), "   ",
			m.styles.muted.Render("MODE "), mode, "   ",
			m.metric("ACTIVE", len(m.networkFlows), m.styles.accent),
			m.metric("SESSIONS", len(m.networkTraffic), m.styles.success),
			m.metric("TCP", tcp, m.styles.generated),
			m.metric("UDP", udp, m.styles.warning),
		)
		if unknown > 0 {
			line += m.metric("UNCLASSIFIED", unknown, m.styles.warning)
		}
		return line
	}
	stats := statsForFlows(m.baseFlows)
	mode := m.styles.success.Bold(true).Render("SESSION")
	if m.networkMode == liveMode {
		mode = m.styles.accent.Bold(true).Render("LIVE")
	}
	if m.contentWidth() < 90 {
		return lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.muted.Render("MODE "), mode, "   ",
			m.metric("ACTIVE", stats.active, m.styles.accent),
			m.metric("IN", stats.inbound, m.styles.success),
			m.metric("OUT", stats.outbound, m.styles.accent),
		)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top,
		m.styles.muted.Render("MODE "), mode, "   ",
		m.metric("ACTIVE", stats.active, m.styles.accent),
		m.metric("IN", stats.inbound, m.styles.success),
		m.metric("OUT", stats.outbound, m.styles.accent),
		m.metric("LISTEN", stats.listen, m.styles.warning),
		m.metric("UDP BOUND", stats.bound, m.styles.generated),
	)
}

func (m Model) renderTab(value tab, title string, count int) string {
	text := fmt.Sprintf("%s  %d", title, count)
	if m.activeTab == value {
		return m.styles.activeTab.Render(text)
	}
	return m.styles.tab.Render(text)
}

func (m Model) metric(name string, value int, style lipgloss.Style) string {
	return m.styles.muted.Render(name+" ") + style.Bold(true).Render(strconv.Itoa(value)) + "   "
}

func (m Model) statusLine(width int) string {
	if errorText := m.errorText(); errorText != "" {
		return m.styles.danger.Render(truncatePlain(errorText, width))
	}
	parts := make([]string, 0, 4)
	if m.activeTab == dnsTab {
		if !m.lastDNS.IsZero() {
			parts = append(parts, "last DNS event "+m.lastDNS.Format("15:04:05"))
		} else if m.dnsErr == nil {
			parts = append(parts, "waiting for plaintext DNS on UDP/TCP 53")
		}
		if m.dnsWarningCount > 0 {
			parts = append(parts, fmt.Sprintf("%d skipped/dropped packets", m.dnsWarningCount))
		}
		if m.dnsWarning != "" {
			parts = append(parts, m.dnsWarning)
		}
		if m.dnsMode == historyDNSMode {
			if len(m.dnsEvents) == 0 {
				parts = append(parts, "waiting for DNS events")
			}
			parts = append(parts, fmt.Sprintf("%d/%d events retained", m.dnsHistory.len(), dnsHistoryLimit))
			if m.dnsFollow {
				parts = append(parts, "following newest; navigate up to hold")
			} else {
				parts = append(parts, "history held; G/end resumes follow")
			}
		} else {
			if len(m.dnsEntries) == 0 {
				parts = append(parts, "no active cached answers")
			} else {
				parts = append(parts, "active cache ordered by name")
			}
		}
		return m.styles.muted.Render(truncatePlain(strings.Join(parts, "  |  "), width))
	}
	if !m.lastSnapshot.IsZero() {
		parts = append(parts, "updated "+m.lastSnapshot.Format("15:04:05"))
	}
	if len(m.flowWarnings)+len(m.scanWarnings) > 0 {
		parts = append(parts, fmt.Sprintf("partial visibility: %d warnings", len(m.flowWarnings)+len(m.scanWarnings)))
	}
	if m.scanning {
		parts = append(parts, "scanning systemd and cron")
	} else if m.packageManager != "" {
		parts = append(parts, "package manifest: "+m.packageManager)
	}
	if len(parts) == 0 {
		parts = append(parts, "waiting for collectors")
	}
	return m.styles.muted.Render(truncatePlain(strings.Join(parts, "  |  "), width))
}

func (m Model) bodyView() string {
	if m.detailOpen {
		return m.detailView()
	}
	height := m.bodyHeight()
	width := m.contentWidth()
	if width < 60 {
		return statusPanel(width, height, m.styles.warning.Render("Terminal too narrow")+"\n"+m.styles.muted.Render("Resize to at least 62 columns."))
	}
	switch m.activeTab {
	case inboundTab, outboundTab:
		if m.collectorErr != nil && m.networkCount() == 0 {
			return statusPanel(width, height, m.styles.danger.Render("Network collector unavailable")+"\n"+m.styles.muted.Render(sanitizeTerminal(m.collectorErr.Error(), false)))
		}
		if m.networkCount() == 0 {
			direction := "outbound"
			if m.activeTab == inboundTab {
				direction = "inbound"
			}
			message := "No " + direction + " session traffic observed"
			if m.networkMode == liveMode {
				message = "No active " + direction + " network sockets observed"
			}
			return statusPanel(width, height, m.styles.muted.Render(message))
		}
		return m.networkTable.View()
	case portsTab:
		if m.collectorErr != nil && len(m.portFlows) == 0 {
			return statusPanel(width, height, m.styles.danger.Render("Port collector unavailable")+"\n"+m.styles.muted.Render(sanitizeTerminal(m.collectorErr.Error(), false)))
		}
		if len(m.portFlows) == 0 {
			return statusPanel(width, height, m.styles.muted.Render("No TCP listeners or UDP bound sockets observed"))
		}
		return m.portsTable.View()
	case dnsTab:
		if m.dnsErr != nil && m.dnsCount() == 0 {
			return statusPanel(width, height, m.styles.danger.Render("DNS eBPF monitor unavailable")+"\n"+m.styles.muted.Render(sanitizeTerminal(m.dnsErr.Error(), false)))
		}
		return m.dnsTable.View()
	case persistenceTab:
		if m.scanning && len(m.findings) == 0 {
			return statusPanel(width, height, m.styles.accent.Render("Scanning systemd units, timers, and cron entries..."))
		}
		if m.scannerErr != nil && len(m.findings) == 0 {
			return statusPanel(width, height, m.styles.danger.Render("Persistence scan unavailable")+"\n"+m.styles.muted.Render(sanitizeTerminal(m.scannerErr.Error(), false)))
		}
		return m.findingsList.View()
	case integrityTab:
		if m.scanning && len(m.integrityFindings) == 0 {
			return statusPanel(width, height, m.styles.accent.Render("Checking persistence files against native package manifests..."))
		}
		if m.scannerErr != nil && len(m.integrityFindings) == 0 {
			return statusPanel(width, height, m.styles.danger.Render("Integrity scan unavailable")+"\n"+m.styles.muted.Render(sanitizeTerminal(m.scannerErr.Error(), false)))
		}
		if len(m.integrityFindings) == 0 {
			return statusPanel(width, height, m.styles.success.Render("All inventoried persistence files with digests match local package metadata"))
		}
		return m.integrityList.View()
	default:
		return ""
	}
}

func (m Model) detailView() string {
	title := m.styles.accent.Bold(true).Render(m.detailTitle) + m.styles.muted.Render("  evidence and attribution")
	content := lipgloss.JoinVertical(lipgloss.Left, title, "", m.detail.View())
	return m.styles.panel.Width(max(1, m.contentWidth()-4)).Height(max(1, m.bodyHeight()-2)).Render(content)
}

func (m Model) footerView() string {
	width := m.contentWidth()
	if m.detailOpen {
		return m.help.ShortHelpView([]key.Binding{m.keys.Back, table.DefaultKeyMap().LineUp, table.DefaultKeyMap().LineDown, m.keys.Quit})
	}
	if m.filtering {
		apply := key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "apply"))
		cancel := key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel"))
		return m.help.ShortHelpView([]key.Binding{apply, cancel, m.keys.Quit})
	}
	m.help.Width = width
	return m.help.View(m)
}

func (m *Model) resizeComponents() {
	if m.width <= 0 || m.height <= 0 {
		return
	}
	width := m.contentWidth()
	m.help.Width = width
	m.filter.Width = max(10, width-8)
	height := m.bodyHeight()

	networkColumns := columnsForNetwork(width)
	if m.networkMode == sessionMode {
		networkColumns = columnsForSession(width)
	}
	portColumns := columnsForPorts(width)
	dnsColumns := columnsForDNS(width)
	if m.dnsMode == historyDNSMode {
		dnsColumns = columnsForDNSHistory(width)
	}
	setColumnsSafely(&m.networkTable, networkColumns)
	m.networkTable.SetWidth(width)
	m.networkTable.SetHeight(height)
	setColumnsSafely(&m.portsTable, portColumns)
	m.portsTable.SetWidth(width)
	m.portsTable.SetHeight(height)
	setColumnsSafely(&m.dnsTable, dnsColumns)
	m.dnsTable.SetWidth(width)
	m.dnsTable.SetHeight(height)
	m.findingsList.SetSize(width, height)
	m.integrityList.SetSize(width, height)
	m.detail.Width = max(1, width-4)
	m.detail.Height = max(1, height-5)
	m.refreshDetailContent()
}

func setColumnsSafely(component *table.Model, columns []table.Column) {
	if len(component.Rows()) > 0 && len(component.Columns()) != len(columns) {
		component.SetRows(nil)
	}
	component.SetColumns(columns)
}

func columnsForDNS(width int) []table.Column {
	if width >= 130 {
		answers := max(20, width-102)
		return []table.Column{
			{Title: "NAME", Width: 28},
			{Title: "TYPE", Width: 7},
			{Title: "ANSWERS", Width: answers},
			{Title: "CACHE", Width: 8},
			{Title: "QUERIES", Width: 7},
			{Title: "RESP", Width: 6},
			{Title: "PROCESS", Width: 18},
			{Title: "DNS SERVER", Width: 20},
		}
	}
	if width >= 95 {
		answers := max(16, width-69)
		return []table.Column{
			{Title: "NAME", Width: 25},
			{Title: "TYPE", Width: 6},
			{Title: "ANSWERS", Width: answers},
			{Title: "CACHE", Width: 8},
			{Title: "QUERIES", Width: 7},
			{Title: "PROCESS", Width: 17},
		}
	}
	answers := max(12, width-48)
	return []table.Column{
		{Title: "NAME", Width: 22},
		{Title: "TYPE", Width: 6},
		{Title: "ANSWERS", Width: answers},
		{Title: "CACHE", Width: 8},
		{Title: "QUERIES", Width: 7},
	}
}

func columnsForDNSHistory(width int) []table.Column {
	if width >= 130 {
		answers := max(16, width-113)
		return []table.Column{
			{Title: "TIME", Width: 12},
			{Title: "DIR", Width: 8},
			{Title: "NET", Width: 5},
			{Title: "NAME", Width: 26},
			{Title: "TYPE", Width: 7},
			{Title: "ANSWER", Width: answers},
			{Title: "RCODE", Width: 9},
			{Title: "PROCESS", Width: 17},
			{Title: "DNS SERVER", Width: 20},
		}
	}
	if width >= 95 {
		answers := max(16, width-79)
		return []table.Column{
			{Title: "TIME", Width: 8},
			{Title: "DIR", Width: 8},
			{Title: "NAME", Width: 25},
			{Title: "TYPE", Width: 6},
			{Title: "ANSWER", Width: answers},
			{Title: "RCODE", Width: 9},
			{Title: "PROCESS", Width: 16},
		}
	}
	answers := max(12, width-48)
	return []table.Column{
		{Title: "TIME", Width: 8},
		{Title: "DIR", Width: 5},
		{Title: "NAME", Width: 22},
		{Title: "ANSWER", Width: answers},
		{Title: "RCODE", Width: 8},
	}
}

func (m Model) networkCount() int {
	if m.networkMode == liveMode {
		return len(m.networkFlows)
	}
	return len(m.networkTraffic)
}

func (m Model) networkCountFor(value tab) int {
	if value == m.networkView {
		return m.networkCount()
	}
	term := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	count := 0
	if m.networkMode == liveMode {
		for _, item := range m.baseFlows {
			if networkTabIncludes(value, item.Connection.Direction) && (term == "" || m.flowMatches(item, term)) {
				count++
			}
		}
		return count
	}
	for _, item := range m.baseTraffic {
		if networkTabIncludes(value, item.LastConnection.Direction) && (term == "" || m.trafficMatches(item, term)) {
			count++
		}
	}
	return count
}

func (m Model) dnsCount() int {
	if m.activeTab != dnsTab {
		if m.dnsMode == historyDNSMode {
			return m.dnsHistory.len()
		}
		count := 0
		for _, entry := range m.baseDNS {
			if entry.Cached {
				count++
			}
		}
		return count
	}
	if m.dnsMode == currentDNSMode {
		return len(m.dnsEntries)
	}
	return len(m.dnsEvents)
}

func (m Model) contentWidth() int {
	return max(20, m.width-2)
}

func (m Model) bodyHeight() int {
	reserved := lipgloss.Height(m.headerView()) + lipgloss.Height(m.footerView())
	return max(3, m.height-reserved)
}

func columnsForNetwork(width int) []table.Column {
	if width >= 130 {
		service := max(10, width-109)
		return []table.Column{
			{Title: "DIR", Width: 6},
			{Title: "NET", Width: 5},
			{Title: "LOCAL", Width: 25},
			{Title: "REMOTE", Width: 25},
			{Title: "STATE", Width: 12},
			{Title: "PROCESS", Width: 20},
			{Title: "SERVICE", Width: service},
			{Title: "AGE", Width: 8},
		}
	}
	if width >= 100 {
		service := max(8, width-91)
		return []table.Column{
			{Title: "DIR", Width: 6},
			{Title: "NET", Width: 5},
			{Title: "LOCAL", Width: 21},
			{Title: "REMOTE", Width: 23},
			{Title: "STATE", Width: 11},
			{Title: "PROCESS", Width: 18},
			{Title: "SERVICE", Width: service},
		}
	}
	remote := max(8, width-52)
	return []table.Column{
		{Title: "DIR", Width: 6},
		{Title: "NET", Width: 5},
		{Title: "LOCAL", Width: 18},
		{Title: "REMOTE", Width: remote},
		{Title: "PROCESS", Width: 18},
	}
}

func columnsForSession(width int) []table.Column {
	if width >= 130 {
		return []table.Column{
			{Title: "DIR", Width: 6},
			{Title: "NET", Width: 5},
			{Title: "SOURCE", Width: 22},
			{Title: "DESTINATION", Width: 28},
			{Title: "PROCESS", Width: 18},
			{Title: "SRC PORTS", Width: 14},
			{Title: "ACTIVE", Width: 6},
			{Title: "CONNS", Width: 6},
			{Title: "SEEN", Width: 6},
		}
	}
	if width >= 100 {
		destination := max(16, width-83)
		return []table.Column{
			{Title: "DIR", Width: 6},
			{Title: "NET", Width: 5},
			{Title: "SOURCE", Width: 18},
			{Title: "DESTINATION", Width: destination},
			{Title: "PROCESS", Width: 17},
			{Title: "SRC PORTS", Width: 12},
			{Title: "ACTIVE", Width: 6},
			{Title: "CONNS", Width: 6},
		}
	}
	destination := max(10, width-51)
	return []table.Column{
		{Title: "DIR", Width: 5},
		{Title: "NET", Width: 5},
		{Title: "DESTINATION", Width: destination},
		{Title: "PROCESS", Width: 16},
		{Title: "SRC PORTS", Width: 10},
		{Title: "CONNS", Width: 5},
		{Title: "ACT", Width: 3},
	}
}

func columnsForPorts(width int) []table.Column {
	if width >= 110 {
		service := max(10, width-81)
		return []table.Column{
			{Title: "NET", Width: 5},
			{Title: "BIND", Width: 28},
			{Title: "TYPE", Width: 10},
			{Title: "PROCESS", Width: 20},
			{Title: "SERVICE", Width: service},
			{Title: "USER", Width: 12},
		}
	}
	if width >= 70 {
		service := max(8, width-54)
		return []table.Column{
			{Title: "NET", Width: 5},
			{Title: "BIND", Width: 25},
			{Title: "PROCESS", Width: 20},
			{Title: "SERVICE", Width: service},
		}
	}
	process := max(8, width-35)
	return []table.Column{
		{Title: "NET", Width: 5},
		{Title: "BIND", Width: 24},
		{Title: "PROCESS", Width: process},
	}
}

func (m Model) rowsForFlows(flows []flow.Flow, columns []table.Column, ports bool) []table.Row {
	rows := make([]table.Row, 0, len(flows))
	for _, item := range flows {
		connection := item.Connection
		owner := primaryOwner(connection)
		row := make(table.Row, 0, len(columns))
		for _, column := range columns {
			switch column.Title {
			case "DIR":
				row = append(row, strings.ToUpper(string(connection.Direction)))
			case "NET":
				row = append(row, strings.ToUpper(connection.Network))
			case "LOCAL", "BIND":
				row = append(row, connection.Local.String())
			case "REMOTE":
				row = append(row, m.endpointWithDNS(connection.Remote))
			case "STATE":
				row = append(row, connection.State)
			case "TYPE":
				if ports {
					row = append(row, strings.ToUpper(string(connection.Direction)))
				} else {
					row = append(row, connection.State)
				}
			case "PROCESS":
				row = append(row, sanitizeTerminal(flow.ProcessLabel(connection), false))
			case "SERVICE":
				row = append(row, sanitizeTerminal(owner.Service, false))
			case "USER":
				row = append(row, sanitizeTerminal(owner.User, false))
			case "AGE":
				row = append(row, compactDuration(time.Since(item.FirstSeen)))
			case "OBS":
				row = append(row, strconv.FormatUint(item.Observations, 10))
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func (m Model) rowsForTraffic(traffic []flow.Traffic, columns []table.Column) []table.Row {
	rows := make([]table.Row, 0, len(traffic))
	for _, item := range traffic {
		connection := item.LastConnection
		row := make(table.Row, 0, len(columns))
		for _, column := range columns {
			switch column.Title {
			case "DIR":
				row = append(row, strings.ToUpper(string(connection.Direction)))
			case "NET":
				row = append(row, strings.ToUpper(connection.Network))
			case "SOURCE":
				row = append(row, trafficSource(connection))
			case "DESTINATION":
				row = append(row, m.trafficDestination(connection))
			case "PROCESS":
				row = append(row, sanitizeTerminal(flow.ProcessLabel(connection), false))
			case "SRC PORTS":
				row = append(row, formatSourcePorts(item.SourcePorts))
			case "ACTIVE", "ACT":
				row = append(row, strconv.Itoa(item.ActiveSockets))
			case "CONNS":
				row = append(row, strconv.FormatUint(item.Connections, 10))
			case "SEEN":
				row = append(row, strconv.FormatUint(item.Observations, 10))
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func rowsForDNS(entries []dnsmon.Entry, columns []table.Column, now time.Time) []table.Row {
	rows := make([]table.Row, 0, len(entries))
	for _, entry := range entries {
		row := make(table.Row, 0, len(columns))
		for _, column := range columns {
			switch column.Title {
			case "NAME":
				row = append(row, sanitizeTerminal(entry.Name, false))
			case "TYPE":
				row = append(row, entry.Type)
			case "ANSWERS":
				row = append(row, sanitizeTerminal(formatDNSAnswers(entry.Answers, now), false))
			case "CACHE":
				row = append(row, dnsCacheState(entry, now))
			case "QUERIES":
				row = append(row, strconv.FormatUint(entry.Queries, 10))
			case "RESP":
				row = append(row, strconv.FormatUint(entry.Responses, 10))
			case "PROCESS":
				row = append(row, sanitizeTerminal(dnsProcessLabel(entry.Process), false))
			case "DNS SERVER":
				row = append(row, entry.Server.String())
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func rowsForDNSEvents(entries []dnsHistoryEntry, columns []table.Column) []table.Row {
	rows := make([]table.Row, 0, len(entries))
	for _, entry := range entries {
		event := entry.event
		name, recordType := dnsEventQuestion(event)
		row := make(table.Row, 0, len(columns))
		for _, column := range columns {
			switch column.Title {
			case "TIME":
				format := "15:04:05"
				if column.Width > 8 {
					format = "15:04:05.000"
				}
				row = append(row, event.CapturedAt.Format(format))
			case "DIR":
				row = append(row, strings.ToUpper(string(event.Direction)))
			case "NET":
				row = append(row, strings.ToUpper(event.Protocol))
			case "NAME":
				row = append(row, sanitizeTerminal(name, false))
			case "TYPE":
				row = append(row, recordType)
			case "ANSWER":
				row = append(row, sanitizeTerminal(formatDNSEventAnswers(event.Answers), false))
			case "RCODE":
				row = append(row, event.RCode)
			case "PROCESS":
				row = append(row, sanitizeTerminal(dnsProcessLabel(event.Process), false))
			case "DNS SERVER":
				row = append(row, dnsEventServer(event).String())
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func (m Model) renderFlowDetail(item flow.Flow) string {
	connection := item.Connection
	lines := []string{
		m.detailField("Flow ID", item.ID),
		m.detailField("Direction", string(connection.Direction)),
		m.detailField("Network", connection.Network),
		m.detailField("Local endpoint", connection.Local.String()),
		m.detailField("Remote endpoint", connection.Remote.String()),
		m.detailField("State", connection.State),
		m.detailField("First seen", item.FirstSeen.Format(time.RFC3339)),
		m.detailField("Last seen", item.LastSeen.Format(time.RFC3339)),
		m.detailField("Observations", strconv.FormatUint(item.Observations, 10)),
		m.detailField("Socket inodes", strings.Join(connection.SocketInodes, ", ")),
	}
	if names := m.hostnames(connection.Remote.Address); len(names) > 0 {
		lines = append(lines, m.detailField("Remote DNS names", strings.Join(names, ", ")))
	}
	if len(connection.Owners) == 0 {
		lines = append(lines, "", m.styles.warning.Render("No process owner was readable. Run as root for broader attribution."))
	}
	for index, owner := range connection.Owners {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("PROCESS %d", index+1)),
			m.detailField("PID", strconv.Itoa(owner.PID)),
			m.detailField("Name", owner.Name),
			m.detailField("User", owner.User),
			m.detailField("Executable", owner.Executable),
			m.detailField("Service", owner.Service),
			m.detailField("Start ticks", strconv.FormatUint(owner.StartTime, 10)),
			m.detailField("Command", owner.Command),
		)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderTrafficDetail(item flow.Traffic) string {
	connection := item.LastConnection
	lines := []string{
		m.detailField("Traffic ID", item.ID),
		m.detailField("Direction", string(connection.Direction)),
		m.detailField("Network", connection.Network),
		m.detailField("Latest source", trafficSource(connection)),
		m.detailField("Destination", trafficDestination(connection)),
		m.detailField("Source ports", formatSourcePorts(item.SourcePorts)),
		m.detailField("Connections", strconv.FormatUint(item.Connections, 10)),
		m.detailField("Observations", strconv.FormatUint(item.Observations, 10)),
		m.detailField("Active sockets", strconv.Itoa(item.ActiveSockets)),
		m.detailField("First seen", item.FirstSeen.Format(time.RFC3339)),
		m.detailField("Last seen", item.LastSeen.Format(time.RFC3339)),
		m.detailField("Latest state", connection.State),
	}
	destination := connection.Remote
	if connection.Direction == observe.DirectionInbound || connection.Direction == observe.DirectionListen || connection.Direction == observe.DirectionBound {
		destination = connection.Local
	}
	if names := m.hostnames(destination.Address); len(names) > 0 {
		lines = append(lines, m.detailField("Destination DNS", strings.Join(names, ", ")))
	}
	for index, owner := range connection.Owners {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("PROCESS %d", index+1)),
			m.detailField("PID", strconv.Itoa(owner.PID)),
			m.detailField("Name", owner.Name),
			m.detailField("User", owner.User),
			m.detailField("Executable", owner.Executable),
			m.detailField("Service", owner.Service),
			m.detailField("Command", owner.Command),
		)
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderDNSDetail(entry dnsmon.Entry) string {
	now := time.Now()
	lines := []string{
		m.detailField("Record ID", entry.ID),
		m.detailField("Name", entry.Name),
		m.detailField("Type", entry.Type),
		m.detailField("Source", entry.Source),
		m.detailField("Cache state", dnsCacheState(entry, now)),
		m.detailField("Queries", strconv.FormatUint(entry.Queries, 10)),
		m.detailField("Responses", strconv.FormatUint(entry.Responses, 10)),
		m.detailField("Last response", entry.LastRCode),
		m.detailField("DNS server", entry.Server.String()),
		m.detailField("First seen", entry.FirstSeen.Format(time.RFC3339)),
		m.detailField("Last seen", entry.LastSeen.Format(time.RFC3339)),
	}
	if !entry.ExpiresAt.IsZero() {
		lines = append(lines, m.detailField("Cache expires", entry.ExpiresAt.Format(time.RFC3339)))
	}
	if entry.Process.PID > 0 || entry.Process.Name != "" {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render("QUERY PROCESS"),
			m.detailField("PID", strconv.Itoa(entry.Process.PID)),
			m.detailField("Name", entry.Process.Name),
			m.detailField("User", entry.Process.User),
			m.detailField("Executable", entry.Process.Executable),
			m.detailField("Service", entry.Process.Service),
			m.detailField("Command", entry.Process.Command),
		)
	}
	for index, answer := range entry.Answers {
		expires := "permanent"
		if !answer.Permanent {
			expires = answer.ExpiresAt.Format(time.RFC3339)
			if !answer.ExpiresAt.After(now) {
				expires += " (expired)"
			}
		}
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("ANSWER %d", index+1)),
			m.detailField("Value", answer.Value),
			m.detailField("TTL", fmt.Sprintf("%ds", answer.TTL)),
			m.detailField("Last seen", answer.LastSeen.Format(time.RFC3339)),
			m.detailField("Expires", expires),
		)
	}
	lines = append(lines, "", m.styles.muted.Render("Observed cache reflects plaintext DNS seen since ProcWire started plus /etc/hosts; DoH and DoT are encrypted."))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderDNSEventDetail(entry dnsHistoryEntry) string {
	event := entry.event
	lines := []string{
		m.detailField("Event ID", strconv.FormatUint(entry.id, 10)),
		m.detailField("Captured", event.CapturedAt.Format(time.RFC3339Nano)),
		m.detailField("Direction", string(event.Direction)),
		m.detailField("Protocol", event.Protocol),
		m.detailField("Transaction ID", fmt.Sprintf("0x%04x (%d)", event.TransactionID, event.TransactionID)),
		m.detailField("Response code", event.RCode),
		m.detailField("Authoritative", strconv.FormatBool(event.Authoritative)),
		m.detailField("Truncated", strconv.FormatBool(event.Truncated)),
		m.detailField("Source", event.Source.String()),
		m.detailField("Destination", event.Destination.String()),
		m.detailField("DNS server", dnsEventServer(event).String()),
		m.detailField("UID", strconv.FormatUint(uint64(event.UID), 10)),
		m.detailField("GID", strconv.FormatUint(uint64(event.GID), 10)),
		m.detailField("Cgroup ID", strconv.FormatUint(event.CgroupID, 10)),
	}
	if event.Process.PID > 0 || event.Process.Name != "" {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render("PROCESS ATTRIBUTION"),
			m.detailField("PID", strconv.Itoa(event.Process.PID)),
			m.detailField("Name", event.Process.Name),
			m.detailField("User", event.Process.User),
			m.detailField("Executable", event.Process.Executable),
			m.detailField("Service", event.Process.Service),
			m.detailField("Command", event.Process.Command),
		)
	}
	for index, question := range event.Questions {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("QUESTION %d", index+1)),
			m.detailField("Name", question.Name),
			m.detailField("Type", question.Type),
			m.detailField("Class", strconv.FormatUint(uint64(question.Class), 10)),
		)
	}
	for index, answer := range event.Answers {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("ANSWER %d", index+1)),
			m.detailField("Section", answer.Section),
			m.detailField("Name", answer.Name),
			m.detailField("Type", answer.Type),
			m.detailField("Class", strconv.FormatUint(uint64(answer.Class), 10)),
			m.detailField("TTL", fmt.Sprintf("%ds", answer.TTL)),
			m.detailField("Value", answer.Value),
		)
	}
	lines = append(lines, "", m.styles.muted.Render("History retains the latest 20,000 parsed DNS events in memory; JSONL recording is the durable event log."))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderFindingDetail(finding persistence.Finding) string {
	lines := []string{
		m.detailField("Name", finding.Name),
		m.detailField("Unit", finding.Unit),
		m.detailField("Mechanism", finding.Mechanism),
		m.detailField("Review level", string(finding.Level)),
		m.detailField("Provenance", string(finding.Provenance)),
		m.detailField("Package", finding.Package),
		m.detailField("Package manager", finding.PackageManager),
		m.detailField("Role", finding.Role),
		m.detailField("Enablement", finding.Enablement),
		m.detailField("Scope", finding.Scope),
		m.detailField("User", finding.User),
		m.detailField("Path", finding.Path),
		m.detailField("Resolved path", finding.ResolvedPath),
		m.detailField("Schedule", finding.Schedule),
		m.detailField("Command", finding.Command),
		m.detailField("Integrity", finding.Integrity),
		m.detailField("Reason", finding.Reason),
		m.detailField("Next step", finding.Recommendation),
	}
	if len(finding.RelatedPaths) > 0 {
		lines = append(lines, m.detailField("Related paths", strings.Join(finding.RelatedPaths, "\n")))
	}
	for index, evidence := range finding.ReferencedFiles {
		lines = append(lines,
			"",
			m.styles.accent.Bold(true).Render(fmt.Sprintf("REFERENCED FILE %d", index+1)),
			m.detailField("Path", evidence.Path),
			m.detailField("Provenance", string(evidence.Provenance)),
			m.detailField("Package", evidence.Package),
			m.detailField("Integrity", evidence.Integrity),
		)
	}
	lines = append(lines, "", m.styles.warning.Render("Package match means this file matches local package metadata. It is not proof against a compromised root or package database."))
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) detailField(label, value string) string {
	label = sanitizeTerminal(label, false)
	value = sanitizeTerminal(value, true)
	if value == "" {
		value = "-"
	}
	valueWidth := max(10, m.detail.Width-19)
	return lipgloss.JoinHorizontal(lipgloss.Top,
		m.styles.label.Render(label),
		m.styles.value.Width(valueWidth).Render(value),
	)
}

type flowStats struct {
	active   int
	inbound  int
	outbound int
	listen   int
	bound    int
}

type dnsStats struct {
	cached    int
	queries   int
	responses int
}

func statsForDNS(entries []dnsmon.Entry) dnsStats {
	stats := dnsStats{}
	for _, entry := range entries {
		if entry.Cached {
			stats.cached++
		}
		stats.queries += int(entry.Queries)
		stats.responses += int(entry.Responses)
	}
	return stats
}

func statsForDNSEvents(history dnsHistory) dnsStats {
	stats := dnsStats{}
	for index := 0; index < history.len(); index++ {
		switch history.at(index).event.Direction {
		case dnsmon.DirectionQuery:
			stats.queries++
		case dnsmon.DirectionResponse:
			stats.responses++
		}
	}
	return stats
}

func statsForFlows(flows []flow.Flow) flowStats {
	stats := flowStats{active: len(flows)}
	for _, item := range flows {
		switch item.Connection.Direction {
		case observe.DirectionInbound:
			stats.inbound++
		case observe.DirectionOutbound:
			stats.outbound++
		case observe.DirectionListen:
			stats.listen++
		case observe.DirectionBound:
			stats.bound++
		}
	}
	return stats
}

func primaryOwner(connection observe.Connection) observe.Process {
	if len(connection.Owners) == 0 {
		return observe.Process{}
	}
	return connection.Owners[0]
}

func trafficSource(connection observe.Connection) string {
	switch connection.Direction {
	case observe.DirectionInbound:
		return connection.Remote.String()
	case observe.DirectionListen, observe.DirectionBound:
		return "-"
	default:
		return connection.Local.String()
	}
}

func trafficDestination(connection observe.Connection) string {
	switch connection.Direction {
	case observe.DirectionInbound, observe.DirectionListen, observe.DirectionBound:
		return connection.Local.String()
	default:
		return connection.Remote.String()
	}
}

func (m Model) trafficDestination(connection observe.Connection) string {
	switch connection.Direction {
	case observe.DirectionInbound, observe.DirectionListen, observe.DirectionBound:
		return m.endpointWithDNS(connection.Local)
	default:
		return m.endpointWithDNS(connection.Remote)
	}
}

func (m Model) endpointWithDNS(endpoint observe.Endpoint) string {
	names := m.hostnames(endpoint.Address)
	if len(names) == 0 {
		return endpoint.String()
	}
	name := names[0]
	if len(names) > 1 {
		name += fmt.Sprintf(" +%d", len(names)-1)
	}
	if endpoint.Port == 0 {
		return name
	}
	return fmt.Sprintf("%s:%d", name, endpoint.Port)
}

func (m Model) hostnames(address netip.Addr) []string {
	if !address.IsValid() {
		return nil
	}
	return m.dnsNames[address.Unmap()]
}

func formatSourcePorts(ports []uint16) string {
	if len(ports) == 0 {
		return "-"
	}
	values := make([]string, 0, min(len(ports), 5))
	for index, port := range ports {
		if index == 4 {
			values = append(values, fmt.Sprintf("+%d", len(ports)-index))
			break
		}
		values = append(values, strconv.Itoa(int(port)))
	}
	return strings.Join(values, ",")
}

func formatDNSAnswers(answers []dnsmon.CachedAnswer, now time.Time) string {
	values := make([]string, 0, min(len(answers), 3))
	remaining := 0
	for _, answer := range answers {
		if !answer.Permanent && !answer.ExpiresAt.After(now) {
			continue
		}
		if len(values) == 2 {
			remaining++
			continue
		}
		values = append(values, answer.Value)
	}
	if remaining > 0 {
		values = append(values, fmt.Sprintf("+%d", remaining))
	}
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}

func dnsEventQuestion(event dnsmon.Event) (string, string) {
	if len(event.Questions) > 0 {
		name := event.Questions[0].Name
		if len(event.Questions) > 1 {
			name += fmt.Sprintf(" +%d", len(event.Questions)-1)
		}
		return name, event.Questions[0].Type
	}
	if len(event.Answers) > 0 {
		return event.Answers[0].Name, event.Answers[0].Type
	}
	return "-", "-"
}

func formatDNSEventAnswers(answers []dnsmon.Answer) string {
	if len(answers) == 0 {
		return "-"
	}
	values := make([]string, 0, min(len(answers), 3))
	for index, answer := range answers {
		if index == 2 {
			values = append(values, fmt.Sprintf("+%d", len(answers)-index))
			break
		}
		values = append(values, answer.Value)
	}
	return strings.Join(values, ", ")
}

func dnsEventServer(event dnsmon.Event) observe.Endpoint {
	if event.Direction == dnsmon.DirectionQuery {
		return event.Destination
	}
	return event.Source
}

func dnsCacheState(entry dnsmon.Entry, now time.Time) string {
	if entry.Source == "hosts" {
		return "HOSTS"
	}
	if entry.Cached {
		return "CACHED"
	}
	if len(entry.Answers) > 0 && !entry.ExpiresAt.After(now) {
		return "EXPIRED"
	}
	return "OBSERVED"
}

func dnsProcessLabel(process observe.Process) string {
	if process.Name != "" && process.PID > 0 {
		return fmt.Sprintf("%s (%d)", process.Name, process.PID)
	}
	if process.Name != "" {
		return process.Name
	}
	if process.PID > 0 {
		return strconv.Itoa(process.PID)
	}
	return "-"
}

func provenanceLabel(value persistence.Provenance) string {
	switch value {
	case persistence.ProvenancePackageMatch:
		return "SYSTEM"
	case persistence.ProvenancePackageModified:
		return "MODIFIED"
	case persistence.ProvenancePackageOwned:
		return "OWNED"
	case persistence.ProvenanceLocal:
		return "LOCAL"
	case persistence.ProvenanceGenerated:
		return "GENERATED"
	default:
		return "UNKNOWN"
	}
}

func compactDuration(duration time.Duration) string {
	if duration < time.Second {
		return "<1s"
	}
	if duration < time.Minute {
		return fmt.Sprintf("%ds", int(duration.Seconds()))
	}
	if duration < time.Hour {
		return fmt.Sprintf("%dm", int(duration.Minutes()))
	}
	if duration < 24*time.Hour {
		return fmt.Sprintf("%dh", int(duration.Hours()))
	}
	return fmt.Sprintf("%dd", int(duration.Hours()/24))
}

func alignSides(left, right string, width int) string {
	gap := max(1, width-lipgloss.Width(left)-lipgloss.Width(right))
	return truncateANSI(left+strings.Repeat(" ", gap)+right, width)
}

func truncateANSI(value string, width int) string {
	if lipgloss.Width(value) <= width {
		return value
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(value)
}

func truncatePlain(value string, width int) string {
	value = sanitizeTerminal(value, false)
	if width <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= width {
		return value
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return string(runes[:width-3]) + "..."
}

func sanitizeTerminal(value string, preserveNewlines bool) string {
	return strings.Map(func(char rune) rune {
		if preserveNewlines && char == '\n' {
			return char
		}
		if char == '\t' {
			return ' '
		}
		if unicode.Is(unicode.Cc, char) || unicode.Is(unicode.Cf, char) {
			return -1
		}
		return char
	}, value)
}

func statusPanel(width, height int, content string) string {
	return lipgloss.Place(max(1, width), max(1, height), lipgloss.Center, lipgloss.Center, content)
}
