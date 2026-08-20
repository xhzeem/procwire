package tui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/flow"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
	"github.com/xhzeem/procwire/internal/runtimecheck"
)

type Recorder interface {
	Record(string, any) error
}

type Config struct {
	Collector      observe.Collector
	DNSMonitor     dnsmon.PacketMonitor
	DNSError       error
	HostsPath      string
	Scanner        persistence.Scanner
	RuntimeScanner runtimecheck.Scanner
	RuntimeSampler runtimecheck.Sampler
	Recorder       Recorder
	ReportPath     string
	Interval       time.Duration
	RunFor         time.Duration
	RuntimeRescan  time.Duration
	Version        string
}

type tab int

type networkMode int
type dnsMode int
type persistenceMode int

const (
	inboundTab tab = iota
	outboundTab
	dnsTab
	portsTab
	persistenceTab
	processesTab
	loaderTab
	tabCount
)

const (
	liveMode networkMode = iota
	sessionMode
)

const (
	currentDNSMode dnsMode = iota
	historyDNSMode
)

const (
	persistenceInventoryMode persistenceMode = iota
	persistenceIntegrityMode
)

// defaultRuntimeRescan is how often the expensive process and loader integrity
// scan repeats on its own. Live sampling keeps the process tab current between
// those scans at the polling interval.
const defaultRuntimeRescan = 30 * time.Second

const dnsHistoryLimit = 20_000
const dnsBatchWindow = 16 * time.Millisecond

type dnsHistoryEntry struct {
	id    uint64
	event dnsmon.Event
}

type dnsHistory struct {
	entries []dnsHistoryEntry
	start   int
	nextID  uint64
}

type processTreeRow struct {
	process     runtimecheck.Process
	depth       int
	hasChildren bool
	collapsed   bool
}

func (history *dnsHistory) append(event dnsmon.Event) dnsHistoryEntry {
	history.nextID++
	entry := dnsHistoryEntry{id: history.nextID, event: event}
	if len(history.entries) < dnsHistoryLimit {
		history.entries = append(history.entries, entry)
		return entry
	}
	history.entries[history.start] = entry
	history.start = (history.start + 1) % len(history.entries)
	return entry
}

func (history dnsHistory) len() int {
	return len(history.entries)
}

func (history dnsHistory) at(index int) dnsHistoryEntry {
	return history.entries[(history.start+index)%len(history.entries)]
}

type Model struct {
	collector      observe.Collector
	dnsMonitor     dnsmon.PacketMonitor
	scanner        persistence.Scanner
	runtimeScanner runtimecheck.Scanner
	runtimeSampler runtimecheck.Sampler
	recorder       Recorder
	store          *flow.Store
	dnsStore       *dnsmon.Store
	interval       time.Duration
	runtimeRescan  time.Duration
	report         string
	version        string
	runFor         time.Duration

	activeTab       tab
	networkView     tab
	networkMode     networkMode
	dnsMode         dnsMode
	persistenceMode persistenceMode
	processMode     processMode
	loaderMode      loaderMode
	processSort     processSort
	trust           trustFilter
	networkTable    table.Model
	dnsTable        table.Model
	portsTable      table.Model
	processTable    table.Model
	findingsList    list.Model
	integrityList   list.Model
	loaderList      list.Model
	detail          viewport.Model
	help            help.Model
	filter          textinput.Model
	keys            keyMap
	styles          styles

	width                 int
	height                int
	baseFlows             []flow.Flow
	networkFlows          []flow.Flow
	baseTraffic           []flow.Traffic
	networkTraffic        []flow.Traffic
	baseDNS               []dnsmon.Entry
	dnsEntries            []dnsmon.Entry
	dnsHistory            dnsHistory
	dnsEvents             []dnsHistoryEntry
	dnsNames              map[netip.Addr][]string
	portFlows             []flow.Flow
	findings              []persistence.Finding
	integrityFindings     []persistence.Finding
	scanProcesses         []runtimecheck.Process
	sampleProcesses       []runtimecheck.ProcessSample
	processes             []runtimecheck.Process
	processRows           []processTreeRow
	processScroll         int
	metrics               map[string]processMetric
	processCPU            map[string]uint64
	memoryTotal           uint64
	loaderFindings        []persistence.Finding
	loaderVisible         []persistence.Finding
	collapsedProcesses    map[string]bool
	packageManager        string
	runtimePackageManager string
	lastSnapshot          time.Time
	lastDNS               time.Time
	lastRuntimeScan       time.Time
	lastSample            time.Time
	flowWarnings          []string
	scanWarnings          []string
	runtimeWarnings       []string
	processCoverage       runtimecheck.ProcessCoverage
	loaderCoverage        runtimecheck.LoaderCoverage
	dnsWarning            string
	dnsWarningCount       uint64
	collectorErr          error
	dnsErr                error
	scannerErr            error
	runtimeScannerErr     error
	runtimeSamplerErr     error
	recorderErr           error
	scanning              bool
	runtimeScanning       bool
	runtimeSampling       bool
	paused                bool
	filtering             bool
	filterBefore          string
	detailOpen            bool
	detailTitle           string
	detailFlowID          string
	detailTrafficID       string
	detailDNSID           string
	detailDNSEventID      uint64
	detailFindingID       string
	detailProcessID       string
	detailLoaderID        string
	dnsFollow             bool
	refreshQueued         bool
	collectorStatus       string
	sampleStatus          string
	legendOpen            bool
}

type snapshotMsg struct {
	snapshot observe.Snapshot
	err      error
}

type scanMsg struct {
	result persistence.Result
	err    error
}

type runtimeScanMsg struct {
	result runtimecheck.Result
	err    error
}

type runtimeSampleMsg struct {
	sample runtimecheck.Sample
	err    error
}

type tickMsg time.Time
type quitMsg struct{}

type dnsMonitorMsg struct {
	packets []dnsmon.Packet
	errors  []error
	closed  bool
}

func New(config Config) Model {
	if config.Interval <= 0 {
		config.Interval = time.Second
	}
	if config.RuntimeRescan == 0 {
		config.RuntimeRescan = defaultRuntimeRescan
	}
	styleSet := newStyles()
	tableStyles := table.DefaultStyles()
	tableStyles.Header = styleSet.tableHeader.PaddingRight(1)
	tableStyles.Cell = styleSet.tableCell.PaddingRight(1)
	tableStyles.Selected = styleSet.tableSelected

	network := table.New(
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(tableStyles),
	)
	dnsTable := table.New(
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(tableStyles),
	)
	ports := table.New(
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(tableStyles),
	)
	processes := table.New(
		table.WithFocused(true),
		table.WithHeight(10),
		table.WithStyles(tableStyles),
	)

	findingList := newFindingList(styleSet)
	integrityList := newFindingList(styleSet)
	loaderList := newFindingList(styleSet)

	filter := textinput.New()
	filter.Prompt = "Filter: "
	filter.Placeholder = "endpoint, process, service, state..."
	filter.CharLimit = 128
	filter.KeyMap.Paste.Unbind()
	filter.PromptStyle = styleSet.accent
	filter.TextStyle = styleSet.normal
	filter.PlaceholderStyle = styleSet.faint
	filter.Cursor.Style = styleSet.accent

	helpModel := help.New()
	helpModel.Styles.ShortKey = styleSet.accent
	helpModel.Styles.ShortDesc = styleSet.muted
	helpModel.Styles.ShortSeparator = styleSet.faint
	helpModel.Styles.FullKey = styleSet.accent
	helpModel.Styles.FullDesc = styleSet.muted
	helpModel.Styles.FullSeparator = styleSet.faint
	helpModel.ShortSeparator = "  "

	dnsStore := dnsmon.NewStore()
	now := time.Now()
	hostsPath := config.HostsPath
	if hostsPath == "" {
		hostsPath = "/etc/hosts"
	}
	dnsWarning := ""
	if err := dnsStore.SeedHosts(hostsPath, now); err != nil {
		dnsWarning = "read hosts cache: " + err.Error()
	}
	baseDNS := dnsStore.Entries(now)

	return Model{
		collector:          config.Collector,
		dnsMonitor:         config.DNSMonitor,
		scanner:            config.Scanner,
		runtimeScanner:     config.RuntimeScanner,
		runtimeSampler:     config.RuntimeSampler,
		recorder:           config.Recorder,
		store:              flow.NewStore(),
		dnsStore:           dnsStore,
		interval:           config.Interval,
		runtimeRescan:      config.RuntimeRescan,
		report:             config.ReportPath,
		version:            config.Version,
		runFor:             config.RunFor,
		networkTable:       network,
		dnsTable:           dnsTable,
		portsTable:         ports,
		processTable:       processes,
		findingsList:       findingList,
		integrityList:      integrityList,
		loaderList:         loaderList,
		detail:             viewport.New(80, 10),
		help:               helpModel,
		filter:             filter,
		keys:               defaultKeyMap(),
		styles:             styleSet,
		activeTab:          outboundTab,
		networkView:        outboundTab,
		networkMode:        sessionMode,
		dnsMode:            historyDNSMode,
		persistenceMode:    persistenceInventoryMode,
		processMode:        processTreeMode,
		loaderMode:         loaderAllMode,
		processSort:        sortByRisk,
		trust:              trustAll,
		dnsFollow:          true,
		baseDNS:            baseDNS,
		dnsNames:           indexDNSNames(baseDNS, now),
		dnsErr:             config.DNSError,
		dnsWarning:         dnsWarning,
		scanning:           true,
		runtimeScanning:    true,
		refreshQueued:      true,
		collapsedProcesses: make(map[string]bool),
		metrics:            make(map[string]processMetric),
		processCPU:         make(map[string]uint64),
	}
}

func newFindingList(styleSet styles) list.Model {
	findingList := list.New(nil, findingDelegate{styles: styleSet}, 80, 10)
	findingList.SetShowTitle(false)
	findingList.SetShowStatusBar(true)
	findingList.SetShowPagination(true)
	findingList.SetShowHelp(false)
	findingList.SetStatusBarItemName("entry", "entries")
	findingList.DisableQuitKeybindings()
	findingList.FilterInput.KeyMap.Paste.Unbind()
	findingList.Styles.StatusBar = styleSet.muted
	findingList.Styles.StatusEmpty = styleSet.muted
	findingList.Styles.StatusBarActiveFilter = styleSet.accent
	findingList.Styles.StatusBarFilterCount = styleSet.muted
	findingList.Styles.PaginationStyle = styleSet.muted
	findingList.Styles.ActivePaginationDot = styleSet.accent
	findingList.Styles.InactivePaginationDot = styleSet.faint
	findingList.Styles.FilterPrompt = styleSet.accent
	findingList.Styles.FilterCursor = styleSet.accent
	findingList.Styles.DefaultFilterCharacterMatch = styleSet.accent
	return findingList
}

func (m Model) Init() tea.Cmd {
	commands := []tea.Cmd{m.collectCmd(), m.scanCmd(), m.runtimeScanCmd(), m.runtimeSampleCmd()}
	if m.dnsMonitor != nil && m.dnsErr == nil {
		commands = append(commands, m.waitDNSCmd())
	}
	if m.runFor > 0 {
		commands = append(commands, tea.Tick(m.runFor, func(time.Time) tea.Msg { return quitMsg{} }))
	}
	return tea.Batch(commands...)
}

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	var commands []tea.Cmd

	switch msg := message.(type) {
	case quitMsg:
		return m, tea.Quit

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeComponents()
		m.syncTables()
		return m, nil

	case snapshotMsg:
		m.refreshQueued = false
		m.collectorErr = msg.err
		m.flowWarnings = msg.snapshot.Warnings
		m.recordCollectorStatus(msg)
		if msg.err == nil {
			m.lastSnapshot = msg.snapshot.CapturedAt
			events := m.store.Reconcile(msg.snapshot)
			m.recordFlowEvents(events)
			if !m.paused {
				m.baseFlows = m.store.Active()
				m.baseTraffic = m.store.History()
			}
			m.refreshDetailContent()
		}
		if !m.paused {
			m.refreshDNS(time.Now())
			m.syncTables()
		}
		commands = append(commands, tickCmd(m.interval))

	case dnsMonitorMsg:
		if msg.closed {
			m.dnsErr = errors.New("DNS eBPF monitor stopped")
			m.recordDNSStatus(false, m.dnsErr)
			break
		}
		for _, err := range msg.errors {
			m.dnsWarning = err.Error()
			m.dnsWarningCount++
			m.record("dns_monitor_warning", map[string]any{"error": err.Error(), "observed_at": time.Now()})
		}
		updatedDNS := false
		newHistory := make([]dnsHistoryEntry, 0, len(msg.packets))
		for _, packet := range msg.packets {
			events, err := dnsmon.Parse(packet)
			if err != nil {
				m.dnsWarning = err.Error()
				m.dnsWarningCount++
				m.record("dns_parse_warning", map[string]any{"error": err.Error(), "observed_at": time.Now()})
			} else {
				for _, event := range events {
					event = m.dnsStore.Apply(event)
					newHistory = append(newHistory, m.dnsHistory.append(event))
					m.lastDNS = event.CapturedAt
					m.record("dns_event", event)
				}
				updatedDNS = true
			}
		}
		if updatedDNS && !m.paused {
			m.refreshDNS(time.Now())
			if m.activeTab == dnsTab && m.dnsMode == historyDNSMode && strings.TrimSpace(m.filter.Value()) == "" {
				m.appendVisibleDNSEvents(newHistory)
			} else {
				m.syncTables()
			}
		}
		if updatedDNS {
			m.refreshDetailContent()
		}
		if m.dnsMonitor != nil {
			commands = append(commands, m.waitDNSCmd())
		}

	case tickMsg:
		if !m.refreshQueued {
			m.refreshQueued = true
			commands = append(commands, m.collectCmd())
		}
		if !m.runtimeSampling && m.runtimeSampler != nil && m.runtimeSamplerErr == nil {
			m.runtimeSampling = true
			commands = append(commands, m.runtimeSampleCmd())
		}
		if !m.runtimeScanning && m.runtimeRescan > 0 && !m.lastRuntimeScan.IsZero() &&
			time.Since(m.lastRuntimeScan) >= m.runtimeRescan {
			m.runtimeScanning = true
			commands = append(commands, m.runtimeScanCmd())
		}

	case scanMsg:
		m.scanning = false
		m.scannerErr = msg.err
		if msg.err == nil {
			m.findings = msg.result.Findings
			m.integrityFindings = integrityOnly(msg.result.Findings)
			m.packageManager = msg.result.PackageManager
			m.scanWarnings = msg.result.Warnings
			items := make([]list.Item, 0, len(m.findings))
			for _, finding := range m.findings {
				items = append(items, findingItem{Finding: finding})
			}
			integrityItems := make([]list.Item, 0, len(m.integrityFindings))
			for _, finding := range m.integrityFindings {
				integrityItems = append(integrityItems, findingItem{Finding: finding})
			}
			m.findingsList.ResetFilter()
			m.integrityList.ResetFilter()
			commands = append(commands, m.findingsList.SetItems(items))
			commands = append(commands, m.integrityList.SetItems(integrityItems))
			m.record("persistence_scan", msg.result)
			m.refreshDetailContent()
		}

	case runtimeScanMsg:
		m.runtimeScanning = false
		m.runtimeScannerErr = msg.err
		if msg.err == nil {
			m.scanProcesses = msg.result.Processes
			m.loaderFindings = msg.result.LoaderFindings
			m.runtimePackageManager = msg.result.PackageManager
			m.runtimeWarnings = msg.result.Warnings
			m.processCoverage = msg.result.ProcessCoverage
			m.loaderCoverage = msg.result.LoaderCoverage
			m.lastRuntimeScan = msg.result.ScannedAt
			m.rebuildProcesses()
			commands = append(commands, m.syncLoaderList())
			m.syncTables()
			m.record("runtime_scan_summary", map[string]any{
				"scanned_at":       msg.result.ScannedAt,
				"package_manager":  msg.result.PackageManager,
				"process_coverage": msg.result.ProcessCoverage,
				"loader_coverage":  msg.result.LoaderCoverage,
				"warnings":         msg.result.Warnings,
			})
			for _, process := range msg.result.Processes {
				m.record("process_observation", process)
			}
			for _, finding := range msg.result.LoaderFindings {
				m.record("loader_finding", finding)
			}
			m.refreshDetailContent()
		}

	case runtimeSampleMsg:
		m.runtimeSampling = false
		m.runtimeSamplerErr = msg.err
		m.recordSampleStatus(msg)
		if msg.err == nil {
			m.applySample(msg.sample)
			if !m.paused {
				m.syncTables()
			}
			m.refreshDetailContent()
		}

	case list.FilterMatchesMsg:
		var command tea.Cmd
		if m.activeTab == loaderTab {
			m.loaderList, command = m.loaderList.Update(msg)
		} else if m.activeTab == persistenceTab && m.persistenceMode == persistenceIntegrityMode {
			m.integrityList, command = m.integrityList.Update(msg)
		} else {
			m.findingsList, command = m.findingsList.Update(msg)
		}
		return m, command
	}

	if msg, ok := message.(tea.KeyMsg); ok {
		if m.legendOpen {
			switch {
			case key.Matches(msg, m.keys.Legend), key.Matches(msg, m.keys.Back):
				m.legendOpen = false
				m.resizeComponents()
				return m, tea.Batch(commands...)
			case key.Matches(msg, m.keys.Quit):
				return m, tea.Quit
			default:
				return m, tea.Batch(commands...)
			}
		}

		if m.detailOpen {
			switch {
			case key.Matches(msg, m.keys.Back), key.Matches(msg, m.keys.Detail):
				m.detailOpen = false
				m.detailFlowID = ""
				m.detailTrafficID = ""
				m.detailDNSID = ""
				m.detailDNSEventID = 0
				m.detailFindingID = ""
				m.detailProcessID = ""
				m.detailLoaderID = ""
				m.resizeComponents()
				return m, tea.Batch(commands...)
			case key.Matches(msg, m.keys.Quit):
				return m, tea.Quit
			}
			var command tea.Cmd
			m.detail, command = m.detail.Update(message)
			commands = append(commands, command)
			return m, tea.Batch(commands...)
		}

		if m.filtering {
			switch msg.String() {
			case "enter":
				m.filtering = false
				m.filter.Blur()
				m.syncTables()
				m.resizeComponents()
				return m, tea.Batch(commands...)
			case "esc":
				m.filtering = false
				m.filter.SetValue(m.filterBefore)
				m.filter.Blur()
				m.syncTables()
				m.resizeComponents()
				return m, tea.Batch(commands...)
			case "ctrl+c":
				return m, tea.Quit
			}
			var command tea.Cmd
			m.filter, command = m.filter.Update(msg)
			m.syncTables()
			commands = append(commands, command)
			return m, tea.Batch(commands...)
		}

		if (m.activeTab == persistenceTab && m.persistenceMode == persistenceInventoryMode && m.findingsList.SettingFilter()) ||
			(m.activeTab == persistenceTab && m.persistenceMode == persistenceIntegrityMode && m.integrityList.SettingFilter()) ||
			(m.activeTab == loaderTab && m.loaderList.SettingFilter()) {
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			var command tea.Cmd
			if m.activeTab == loaderTab {
				m.loaderList, command = m.loaderList.Update(msg)
			} else if m.persistenceMode == persistenceIntegrityMode {
				m.integrityList, command = m.integrityList.Update(msg)
			} else {
				m.findingsList, command = m.findingsList.Update(msg)
			}
			commands = append(commands, command)
			return m, tea.Batch(commands...)
		}

		switch {
		case key.Matches(msg, m.keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, m.keys.NextTab):
			m.activeTab = (m.activeTab + 1) % tabCount
			m.rememberNetworkView()
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.PreviousTab):
			m.activeTab = (m.activeTab + tabCount - 1) % tabCount
			m.rememberNetworkView()
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Inbound):
			m.activeTab = inboundTab
			m.rememberNetworkView()
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Outbound):
			m.activeTab = outboundTab
			m.rememberNetworkView()
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.DNS):
			m.activeTab = dnsTab
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Ports):
			m.activeTab = portsTab
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Persistence):
			m.activeTab = persistenceTab
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Processes):
			m.activeTab = processesTab
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Loader):
			m.activeTab = loaderTab
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Pause):
			m.paused = !m.paused
			if !m.paused {
				m.baseFlows = m.store.Active()
				m.baseTraffic = m.store.History()
				m.refreshDNS(time.Now())
				m.syncTables()
			}
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Mode) && isNetworkTab(m.activeTab):
			if m.networkMode == liveMode {
				m.networkMode = sessionMode
			} else {
				m.networkMode = liveMode
			}
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Mode) && m.activeTab == dnsTab:
			if m.dnsMode == currentDNSMode {
				m.dnsMode = historyDNSMode
				m.dnsFollow = true
			} else {
				m.dnsMode = currentDNSMode
			}
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Mode) && m.activeTab == persistenceTab:
			if m.persistenceMode == persistenceInventoryMode {
				m.persistenceMode = persistenceIntegrityMode
			} else {
				m.persistenceMode = persistenceInventoryMode
			}
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Mode) && m.activeTab == processesTab:
			m.processMode = (m.processMode + 1) % processModeCount
			if m.processMode == processLiveMode {
				m.processSort = sortByCPU
			} else {
				m.processSort = sortByRisk
			}
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Mode) && m.activeTab == loaderTab:
			m.loaderMode = (m.loaderMode + 1) % loaderModeCount
			commands = append(commands, m.syncLoaderList())
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Trust) && (m.activeTab == processesTab || m.activeTab == loaderTab):
			m.trust = (m.trust + 1) % trustFilterCount
			if m.activeTab == loaderTab {
				commands = append(commands, m.syncLoaderList())
			}
			m.resizeComponents()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Sort) && m.activeTab == processesTab && m.processMode.flat():
			m.processSort = (m.processSort + 1) % processSortCount
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Collapse) && m.activeTab == processesTab && m.processMode == processTreeMode:
			m.toggleSelectedProcess()
			m.syncTables()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Legend):
			m.legendOpen = true
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Filter) && m.activeTab != persistenceTab && m.activeTab != loaderTab:
			m.filterBefore = m.filter.Value()
			m.filtering = true
			commands = append(commands, m.filter.Focus())
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.ClearFilter) && m.activeTab != persistenceTab && m.activeTab != loaderTab:
			m.filter.Reset()
			m.syncTables()
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Detail):
			m.openSelectedDetail()
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Help):
			m.help.ShowAll = !m.help.ShowAll
			m.resizeComponents()
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Refresh) && m.activeTab == persistenceTab && !m.scanning:
			m.scanning = true
			commands = append(commands, m.scanCmd())
			return m, tea.Batch(commands...)
		case key.Matches(msg, m.keys.Refresh) && (m.activeTab == processesTab || m.activeTab == loaderTab) && !m.runtimeScanning:
			m.runtimeScanning = true
			commands = append(commands, m.runtimeScanCmd())
			return m, tea.Batch(commands...)
		}
	}

	var command tea.Cmd
	switch m.activeTab {
	case inboundTab, outboundTab:
		m.networkTable, command = m.networkTable.Update(message)
	case dnsTab:
		m.dnsTable, command = m.dnsTable.Update(message)
		if _, navigated := message.(tea.KeyMsg); navigated && m.dnsMode == historyDNSMode {
			m.dnsFollow = len(m.dnsEvents) == 0 || m.dnsTable.Cursor() == len(m.dnsEvents)-1
		}
	case portsTab:
		m.portsTable, command = m.portsTable.Update(message)
	case persistenceTab:
		if m.persistenceMode == persistenceIntegrityMode {
			m.integrityList, command = m.integrityList.Update(message)
		} else {
			m.findingsList, command = m.findingsList.Update(message)
		}
	case processesTab:
		m.processTable, command = m.processTable.Update(message)
		m.clampProcessScroll()
	case loaderTab:
		m.loaderList, command = m.loaderList.Update(message)
	}
	commands = append(commands, command)
	return m, tea.Batch(commands...)
}

func (m Model) collectCmd() tea.Cmd {
	return func() tea.Msg {
		if m.collector == nil {
			return snapshotMsg{err: errors.New("network collector is not configured")}
		}
		snapshot, err := m.collector.Snapshot(context.Background())
		return snapshotMsg{snapshot: snapshot, err: err}
	}
}

func (m Model) scanCmd() tea.Cmd {
	return func() tea.Msg {
		if m.scanner == nil {
			return scanMsg{err: errors.New("persistence scanner is not configured")}
		}
		result, err := m.scanner.Scan(context.Background())
		return scanMsg{result: result, err: err}
	}
}

func (m Model) runtimeScanCmd() tea.Cmd {
	return func() tea.Msg {
		if m.runtimeScanner == nil {
			return runtimeScanMsg{err: errors.New("runtime integrity scanner is not configured")}
		}
		result, err := m.runtimeScanner.Scan(context.Background())
		return runtimeScanMsg{result: result, err: err}
	}
}

func (m Model) runtimeSampleCmd() tea.Cmd {
	if m.runtimeSampler == nil {
		return nil
	}
	return func() tea.Msg {
		sample, err := m.runtimeSampler.Sample(context.Background())
		return runtimeSampleMsg{sample: sample, err: err}
	}
}

func (m Model) waitDNSCmd() tea.Cmd {
	return func() tea.Msg {
		message := dnsMonitorMsg{}
		packets := m.dnsMonitor.Packets()
		errors := m.dnsMonitor.Errors()
		select {
		case packet, ok := <-packets:
			if !ok {
				return dnsMonitorMsg{closed: true}
			}
			message.packets = append(message.packets, packet)
		case err, ok := <-errors:
			if !ok {
				return dnsMonitorMsg{closed: true}
			}
			message.errors = append(message.errors, err)
		}
		timer := time.NewTimer(dnsBatchWindow)
		defer timer.Stop()
		for len(message.packets)+len(message.errors) < 512 {
			select {
			case packet, ok := <-packets:
				if !ok {
					return message
				}
				message.packets = append(message.packets, packet)
			case err, ok := <-errors:
				if !ok {
					return message
				}
				message.errors = append(message.errors, err)
			case <-timer.C:
				return message
			}
		}
		return message
	}
}

func tickCmd(interval time.Duration) tea.Cmd {
	return tea.Tick(interval, func(now time.Time) tea.Msg { return tickMsg(now) })
}

func (m *Model) recordFlowEvents(events []flow.Event) {
	for _, event := range events {
		m.record(string(event.Type), event)
	}
}

func (m *Model) recordDNSStatus(active bool, err error) {
	m.record("dns_monitor_status", map[string]any{
		"active": active,
		"error":  errorString(err),
	})
}

// recordSampleStatus writes one record the first time live sampling reports a
// result and again whenever its health changes, so a report shows whether the
// process view was live without a record per interval.
func (m *Model) recordSampleStatus(message runtimeSampleMsg) {
	status := "active"
	if message.err != nil {
		status = message.err.Error()
	}
	if status == m.sampleStatus {
		return
	}
	m.sampleStatus = status
	m.record("runtime_sample_status", map[string]any{
		"active":             message.err == nil,
		"error":              errorString(message.err),
		"observed_at":        time.Now(),
		"visible":            message.sample.Visible,
		"sampled":            len(message.sample.Processes),
		"unreadable":         message.sample.UnreadableRecords,
		"clock_ticks":        message.sample.ClockTicks,
		"memory_total_bytes": message.sample.MemoryTotalBytes,
	})
}

func (m *Model) record(kind string, data any) {
	if m.recorder == nil || m.recorderErr != nil {
		return
	}
	if err := m.recorder.Record(kind, data); err != nil {
		m.recorderErr = err
	}
}

func (m *Model) recordCollectorStatus(message snapshotMsg) {
	parts := append([]string(nil), message.snapshot.Warnings...)
	if message.err != nil {
		parts = append(parts, message.err.Error())
	}
	status := strings.Join(parts, "\n")
	if status == m.collectorStatus {
		return
	}
	previous := m.collectorStatus
	m.collectorStatus = status
	if status == "" && previous == "" {
		return
	}
	m.record("collector_status", map[string]any{
		"healthy":  message.err == nil,
		"error":    errorString(message.err),
		"warnings": message.snapshot.Warnings,
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (m *Model) syncTables() {
	networkID := m.selectedNetworkID()
	portID := selectedFlowID(m.portsTable, m.portFlows)
	processID := selectedProcessID(m.processTable, m.processRows)
	term := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	m.networkFlows = m.networkFlows[:0]
	m.networkTraffic = m.networkTraffic[:0]
	m.portFlows = m.portFlows[:0]
	for _, item := range m.baseFlows {
		if term != "" && !m.flowMatches(item, term) {
			continue
		}
		if item.Connection.Direction == observe.DirectionListen || item.Connection.Direction == observe.DirectionBound {
			m.portFlows = append(m.portFlows, item)
		}
		if networkTabIncludes(m.networkView, item.Connection.Direction) {
			m.networkFlows = append(m.networkFlows, item)
		}
	}
	for _, item := range m.baseTraffic {
		if term != "" && !m.trafficMatches(item, term) {
			continue
		}
		if networkTabIncludes(m.networkView, item.LastConnection.Direction) {
			m.networkTraffic = append(m.networkTraffic, item)
		}
	}
	if m.networkMode == liveMode {
		m.networkTable.SetRows(m.rowsForFlows(m.networkFlows, m.networkTable.Columns(), false))
	} else {
		m.networkTable.SetRows(m.rowsForTraffic(m.networkTraffic, m.networkTable.Columns()))
	}
	m.portsTable.SetRows(m.rowsForFlows(m.portFlows, m.portsTable.Columns(), true))
	if m.activeTab == dnsTab {
		m.syncDNSTable(term)
	}
	m.syncProcessTable(term)
	m.restoreNetworkSelection(networkID)
	restoreFlowSelection(&m.portsTable, m.portFlows, portID)
	restoreProcessSelection(&m.processTable, m.processRows, processID)
}

func (m *Model) syncProcessTable(term string) {
	if m.processMode.flat() {
		m.syncFlatProcessTable(term)
		return
	}
	byPID := make(map[int]runtimecheck.Process, len(m.processes))
	children := make(map[int][]runtimecheck.Process)
	for _, process := range m.processes {
		byPID[process.PID] = process
		children[process.PPID] = append(children[process.PPID], process)
	}
	for parent := range children {
		sort.Slice(children[parent], func(i, j int) bool { return children[parent][i].PID < children[parent][j].PID })
	}
	// A filtered tree keeps every ancestor of a match so the hierarchy that
	// leads to a suspicious process stays readable.
	filtered := term != "" || m.trust != trustAll
	included := make(map[string]bool, len(m.processes))
	if filtered {
		for _, process := range m.processes {
			if !m.processVisible(process, term) {
				continue
			}
			for current, seen := process, make(map[int]bool); current.PID > 0 && !seen[current.PID]; {
				seen[current.PID] = true
				included[current.ID] = true
				parent, found := byPID[current.PPID]
				if !found {
					break
				}
				current = parent
			}
		}
	}
	rows := make([]processTreeRow, 0, len(m.processes))
	visited := make(map[string]bool, len(m.processes))
	var hideDescendants func(int)
	hideDescendants = func(parentPID int) {
		for _, child := range children[parentPID] {
			if visited[child.ID] {
				continue
			}
			visited[child.ID] = true
			hideDescendants(child.PID)
		}
	}
	var walk func(runtimecheck.Process, int)
	walk = func(process runtimecheck.Process, depth int) {
		if visited[process.ID] {
			return
		}
		visited[process.ID] = true
		if filtered && !included[process.ID] {
			return
		}
		hasChildren := len(children[process.PID]) > 0
		collapsed := !filtered && m.collapsedProcesses[process.ID]
		rows = append(rows, processTreeRow{process: process, depth: min(depth, 48), hasChildren: hasChildren, collapsed: collapsed})
		if collapsed {
			hideDescendants(process.PID)
			return
		}
		for _, child := range children[process.PID] {
			walk(child, depth+1)
		}
	}
	for _, process := range m.processes {
		if process.PPID <= 0 || process.PPID == process.PID {
			walk(process, 0)
			continue
		}
		if _, found := byPID[process.PPID]; !found {
			walk(process, 0)
		}
	}
	for _, process := range m.processes {
		walk(process, 0)
	}
	m.processRows = rows
	m.processTable.SetRows(m.rowsForProcesses(rows, m.processTable.Columns()))
	m.clampProcessScroll()
}

// syncFlatProcessTable builds the top-style live and risk views: one row per
// process, ranked by the active sort instead of by hierarchy.
func (m *Model) syncFlatProcessTable(term string) {
	rows := make([]processTreeRow, 0, len(m.processes))
	for _, process := range m.processes {
		if !m.processVisible(process, term) {
			continue
		}
		if m.processMode == processRiskMode && !processSuspect(process) {
			continue
		}
		rows = append(rows, processTreeRow{process: process})
	}
	m.sortProcessRows(rows, m.processSort)
	m.processRows = rows
	m.processTable.SetRows(m.rowsForProcesses(rows, m.processTable.Columns()))
	m.clampProcessScroll()
}

// clampProcessScroll keeps the cursor inside the drawn window. The process
// table is rendered here rather than by bubbles, so its scroll offset is
// tracked here too.
func (m *Model) clampProcessScroll() {
	visible := max(1, m.bodyHeight()-2)
	cursor := m.processTable.Cursor()
	if cursor < m.processScroll {
		m.processScroll = cursor
	}
	if cursor >= m.processScroll+visible {
		m.processScroll = cursor - visible + 1
	}
	m.processScroll = min(m.processScroll, max(0, len(m.processRows)-visible))
	m.processScroll = max(m.processScroll, 0)
}

func (m Model) processVisible(process runtimecheck.Process, term string) bool {
	if term != "" && !processMatches(process, term) {
		return false
	}
	return m.trust.matchesProcess(process)
}

// syncLoaderList reapplies the loader mode and trust filter to the findings
// the last runtime scan produced.
func (m *Model) syncLoaderList() tea.Cmd {
	m.loaderVisible = make([]persistence.Finding, 0, len(m.loaderFindings))
	for _, finding := range m.loaderFindings {
		if !m.loaderMode.matches(finding) || !m.trust.matchesFinding(finding) {
			continue
		}
		m.loaderVisible = append(m.loaderVisible, finding)
	}
	items := make([]list.Item, 0, len(m.loaderVisible))
	for _, finding := range m.loaderVisible {
		items = append(items, findingItem{Finding: finding})
	}
	m.loaderList.ResetFilter()
	return m.loaderList.SetItems(items)
}

// applySample folds a cheap procfs sample into the live metrics and merges it
// with the last integrity scan so processes appear and disappear immediately.
func (m *Model) applySample(sample runtimecheck.Sample) {
	ticks := float64(sample.ClockTicks)
	if ticks <= 0 {
		ticks = 100
	}
	elapsed := sample.CapturedAt.Sub(m.lastSample).Seconds()
	if m.lastSample.IsZero() {
		elapsed = 0
	}
	if sample.MemoryTotalBytes > 0 {
		m.memoryTotal = sample.MemoryTotalBytes
	}
	metrics := make(map[string]processMetric, len(sample.Processes))
	cpuTicks := make(map[string]uint64, len(sample.Processes))
	for _, entry := range sample.Processes {
		id := entry.ID()
		metric := processMetric{
			sampled:    true,
			rssBytes:   entry.RSSBytes,
			threads:    entry.Threads,
			state:      entry.State,
			cpuSeconds: float64(entry.CPUTicks) / ticks,
		}
		if m.memoryTotal > 0 {
			metric.memPercent = float64(entry.RSSBytes) / float64(m.memoryTotal) * 100
		}
		previous, found := m.processCPU[id]
		switch {
		case found && elapsed >= 0.05 && entry.CPUTicks >= previous:
			metric.cpuPercent = float64(entry.CPUTicks-previous) / ticks / elapsed * 100
			metric.hasCPU = true
		case elapsed < 0.05:
			// Two samples landed in the same instant; keep the last usable
			// rate rather than dividing by a near-zero interval.
			metric.cpuPercent = m.metrics[id].cpuPercent
			metric.hasCPU = m.metrics[id].hasCPU
		}
		if elapsed >= 0.05 || !found {
			cpuTicks[id] = entry.CPUTicks
		} else {
			cpuTicks[id] = previous
		}
		metrics[id] = metric
	}
	m.metrics = metrics
	m.processCPU = cpuTicks
	if elapsed >= 0.05 || m.lastSample.IsZero() {
		m.lastSample = sample.CapturedAt
	}
	m.recordSampleChurn(sample)
	m.sampleProcesses = sample.Processes
	m.rebuildProcesses()
}

// recordSampleChurn writes the processes that appeared or exited since the
// previous sample. Integrity scans are minutes apart, so this is the only
// durable record of a process that starts and exits between them.
func (m *Model) recordSampleChurn(sample runtimecheck.Sample) {
	if m.recorder == nil || len(m.sampleProcesses) == 0 {
		return
	}
	previous := make(map[string]struct{}, len(m.sampleProcesses))
	for _, entry := range m.sampleProcesses {
		previous[entry.ID()] = struct{}{}
	}
	current := make(map[string]struct{}, len(sample.Processes))
	for _, entry := range sample.Processes {
		current[entry.ID()] = struct{}{}
	}
	for _, entry := range sample.Processes {
		if _, found := previous[entry.ID()]; !found {
			m.record("process_started", map[string]any{"observed_at": sample.CapturedAt, "process": entry})
		}
	}
	for _, entry := range m.sampleProcesses {
		if _, found := current[entry.ID()]; !found {
			m.record("process_exited", map[string]any{"observed_at": sample.CapturedAt, "process": entry})
		}
	}
}

// rebuildProcesses joins the last integrity scan with the last live sample.
// The sample decides which processes exist right now; the scan supplies the
// provenance and integrity evidence for the ones it has already verified.
func (m *Model) rebuildProcesses() {
	if len(m.sampleProcesses) == 0 {
		m.processes = m.scanProcesses
		return
	}
	verified := make(map[string]runtimecheck.Process, len(m.scanProcesses))
	for _, process := range m.scanProcesses {
		verified[process.ID] = process
	}
	scanned := !m.lastRuntimeScan.IsZero()
	processes := make([]runtimecheck.Process, 0, len(m.sampleProcesses))
	for _, entry := range m.sampleProcesses {
		process, found := verified[entry.ID()]
		if !found {
			processes = append(processes, sampledProcess(entry, scanned))
			continue
		}
		if entry.State != "" {
			process.State = entry.State
		}
		processes = append(processes, process)
	}
	m.processes = processes
}

func processMatches(process runtimecheck.Process, term string) bool {
	values := []string{
		process.ID,
		strconv.Itoa(process.PID),
		strconv.Itoa(process.PPID),
		process.Name,
		process.User,
		process.Executable,
		process.Command,
		process.Service,
		string(process.Provenance),
		process.Package,
		process.Integrity,
		process.Reason,
		strings.Join(process.Flags, " "),
	}
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), term)
}

func selectedProcessID(component table.Model, rows []processTreeRow) string {
	index := component.Cursor()
	if index < 0 || index >= len(rows) {
		return ""
	}
	return rows[index].process.ID
}

func restoreProcessSelection(component *table.Model, rows []processTreeRow, id string) {
	if id != "" {
		for index := range rows {
			if rows[index].process.ID == id {
				component.SetCursor(index)
				return
			}
		}
	}
	clampTableCursor(component, len(rows))
}

func (m *Model) toggleSelectedProcess() {
	index := m.processTable.Cursor()
	if index < 0 || index >= len(m.processRows) || !m.processRows[index].hasChildren {
		return
	}
	id := m.processRows[index].process.ID
	if m.collapsedProcesses[id] {
		delete(m.collapsedProcesses, id)
	} else {
		m.collapsedProcesses[id] = true
	}
}

func (m *Model) syncDNSTable(term string) {
	if m.dnsMode == currentDNSMode {
		dnsID := selectedDNSID(m.dnsTable, m.dnsEntries)
		m.dnsEntries = m.dnsEntries[:0]
		for _, entry := range m.baseDNS {
			if !entry.Cached || term != "" && !dnsMatches(entry, term) {
				continue
			}
			m.dnsEntries = append(m.dnsEntries, entry)
		}
		m.dnsTable.SetRows(rowsForDNS(m.dnsEntries, m.dnsTable.Columns(), time.Now()))
		restoreDNSSelection(&m.dnsTable, m.dnsEntries, dnsID)
		return
	}
	dnsEventID := selectedDNSEventID(m.dnsTable, m.dnsEvents)
	m.dnsEvents = m.dnsEvents[:0]
	for index := 0; index < m.dnsHistory.len(); index++ {
		entry := m.dnsHistory.at(index)
		if term != "" && !dnsEventMatches(entry.event, term) {
			continue
		}
		m.dnsEvents = append(m.dnsEvents, entry)
	}
	m.dnsTable.SetRows(rowsForDNSEvents(m.dnsEvents, m.dnsTable.Columns()))
	restoreDNSEventSelection(&m.dnsTable, m.dnsEvents, dnsEventID)
	if m.dnsFollow && len(m.dnsEvents) > 0 {
		m.dnsTable.SetCursor(len(m.dnsEvents) - 1)
	}
}

func (m *Model) appendVisibleDNSEvents(entries []dnsHistoryEntry) {
	if len(entries) == 0 {
		return
	}
	selectedID := selectedDNSEventID(m.dnsTable, m.dnsEvents)
	m.dnsEvents = append(m.dnsEvents, entries...)
	rows := append(m.dnsTable.Rows(), rowsForDNSEvents(entries, m.dnsTable.Columns())...)
	if overflow := len(m.dnsEvents) - dnsHistoryLimit; overflow > 0 {
		m.dnsEvents = m.dnsEvents[overflow:]
		rows = rows[overflow:]
	}
	m.dnsTable.SetRows(rows)
	if m.dnsFollow {
		m.dnsTable.SetCursor(len(m.dnsEvents) - 1)
		return
	}
	restoreDNSEventSelection(&m.dnsTable, m.dnsEvents, selectedID)
}

func isNetworkTab(value tab) bool {
	return value == inboundTab || value == outboundTab
}

func (m *Model) rememberNetworkView() {
	if isNetworkTab(m.activeTab) {
		m.networkView = m.activeTab
	}
}

func networkTabIncludes(value tab, direction observe.Direction) bool {
	if value == inboundTab {
		return direction == observe.DirectionInbound
	}
	return direction == observe.DirectionOutbound || direction == observe.DirectionUnknown
}

func (m *Model) refreshDNS(now time.Time) {
	m.baseDNS = m.dnsStore.Entries(now)
	sort.Slice(m.baseDNS, func(i, j int) bool {
		if m.baseDNS[i].Name == m.baseDNS[j].Name {
			return m.baseDNS[i].Type < m.baseDNS[j].Type
		}
		return m.baseDNS[i].Name < m.baseDNS[j].Name
	})
	m.dnsNames = indexDNSNames(m.baseDNS, now)
}

func indexDNSNames(entries []dnsmon.Entry, now time.Time) map[netip.Addr][]string {
	index := make(map[netip.Addr][]string)
	for _, entry := range entries {
		if entry.Type != "A" && entry.Type != "AAAA" {
			continue
		}
		for _, address := range entry.Addresses(now) {
			address = address.Unmap()
			names := index[address]
			if len(names) == 0 || names[len(names)-1] != entry.Name {
				index[address] = append(names, entry.Name)
			}
		}
	}
	for address := range index {
		sort.Strings(index[address])
		index[address] = compactStrings(index[address])
	}
	return index
}

func compactStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func dnsMatches(entry dnsmon.Entry, term string) bool {
	values := []string{
		entry.ID,
		entry.Name,
		entry.Type,
		entry.Source,
		entry.LastRCode,
		entry.Server.String(),
		entry.Process.Name,
		entry.Process.Executable,
		entry.Process.Command,
		entry.Process.User,
		entry.Process.Service,
	}
	for _, answer := range entry.Answers {
		values = append(values, answer.Value)
	}
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), term)
}

func dnsEventMatches(event dnsmon.Event, term string) bool {
	values := []string{
		string(event.Direction),
		event.Protocol,
		strconv.FormatUint(uint64(event.TransactionID), 10),
		event.RCode,
		event.Source.String(),
		event.Destination.String(),
		strconv.FormatUint(uint64(event.UID), 10),
		strconv.FormatUint(uint64(event.GID), 10),
		strconv.FormatUint(event.CgroupID, 10),
		event.Process.Name,
		event.Process.Executable,
		event.Process.Command,
		event.Process.User,
		event.Process.Service,
	}
	for _, question := range event.Questions {
		values = append(values, question.Name, question.Type)
	}
	for _, answer := range event.Answers {
		values = append(values, answer.Name, answer.Type, answer.Value, answer.Section)
	}
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), term)
}

func (m Model) trafficMatches(item flow.Traffic, term string) bool {
	connection := item.LastConnection
	values := []string{
		item.ID,
		connection.Network,
		connection.Local.String(),
		connection.Remote.String(),
		connection.State,
		string(connection.Direction),
		flow.ProcessLabel(connection),
		formatSourcePorts(item.SourcePorts),
	}
	for _, owner := range connection.Owners {
		values = append(values, owner.Name, owner.Executable, owner.Command, owner.User, owner.Service)
	}
	values = append(values, m.hostnames(connection.Local.Address)...)
	values = append(values, m.hostnames(connection.Remote.Address)...)
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), term)
}

func (m Model) selectedNetworkID() string {
	index := m.networkTable.Cursor()
	if m.networkMode == liveMode {
		if index >= 0 && index < len(m.networkFlows) {
			return m.networkFlows[index].ID
		}
		return ""
	}
	if index >= 0 && index < len(m.networkTraffic) {
		return m.networkTraffic[index].ID
	}
	return ""
}

func (m *Model) restoreNetworkSelection(id string) {
	if m.networkMode == liveMode {
		restoreFlowSelection(&m.networkTable, m.networkFlows, id)
		return
	}
	if len(m.networkTraffic) > 0 && m.networkTable.Cursor() < 0 {
		m.networkTable.SetCursor(0)
	}
	for index := range m.networkTraffic {
		if m.networkTraffic[index].ID == id {
			m.networkTable.SetCursor(index)
			return
		}
	}
	clampTableCursor(&m.networkTable, len(m.networkTraffic))
}

func (m Model) flowMatches(item flow.Flow, term string) bool {
	connection := item.Connection
	values := []string{
		item.ID,
		connection.Network,
		connection.Local.String(),
		connection.Remote.String(),
		connection.State,
		string(connection.Direction),
		flow.ProcessLabel(connection),
	}
	for _, owner := range connection.Owners {
		values = append(values, owner.Name, owner.Executable, owner.Command, owner.User, owner.Service)
	}
	values = append(values, m.hostnames(connection.Local.Address)...)
	values = append(values, m.hostnames(connection.Remote.Address)...)
	return strings.Contains(strings.ToLower(strings.Join(values, " ")), term)
}

func selectedFlowID(component table.Model, flows []flow.Flow) string {
	index := component.Cursor()
	if index < 0 || index >= len(flows) {
		return ""
	}
	return flows[index].ID
}

func restoreFlowSelection(component *table.Model, flows []flow.Flow, id string) {
	if id != "" {
		for index := range flows {
			if flows[index].ID == id {
				component.SetCursor(index)
				return
			}
		}
	}
	clampTableCursor(component, len(flows))
}

func selectedDNSID(component table.Model, entries []dnsmon.Entry) string {
	index := component.Cursor()
	if index < 0 || index >= len(entries) {
		return ""
	}
	return entries[index].ID
}

func restoreDNSSelection(component *table.Model, entries []dnsmon.Entry, id string) {
	if id != "" {
		for index := range entries {
			if entries[index].ID == id {
				component.SetCursor(index)
				return
			}
		}
	}
	clampTableCursor(component, len(entries))
}

func selectedDNSEventID(component table.Model, events []dnsHistoryEntry) uint64 {
	index := component.Cursor()
	if index < 0 || index >= len(events) {
		return 0
	}
	return events[index].id
}

func restoreDNSEventSelection(component *table.Model, events []dnsHistoryEntry, id uint64) {
	if id != 0 {
		for index := range events {
			if events[index].id == id {
				component.SetCursor(index)
				return
			}
		}
	}
	clampTableCursor(component, len(events))
}

func clampTableCursor(component *table.Model, rowCount int) {
	if rowCount == 0 {
		component.SetCursor(0)
		return
	}
	component.SetCursor(min(max(component.Cursor(), 0), rowCount-1))
}

func (m *Model) openSelectedDetail() {
	content := ""
	switch m.activeTab {
	case inboundTab, outboundTab:
		index := m.networkTable.Cursor()
		if m.networkMode == liveMode && index >= 0 && index < len(m.networkFlows) {
			m.detailTitle = "Connection"
			m.detailFlowID = m.networkFlows[index].ID
			content = m.renderFlowDetail(m.networkFlows[index])
		} else if m.networkMode == sessionMode && index >= 0 && index < len(m.networkTraffic) {
			m.detailTitle = "Session Traffic"
			m.detailTrafficID = m.networkTraffic[index].ID
			content = m.renderTrafficDetail(m.networkTraffic[index])
		}
	case portsTab:
		index := m.portsTable.Cursor()
		if index >= 0 && index < len(m.portFlows) {
			m.detailTitle = "Open Port"
			m.detailFlowID = m.portFlows[index].ID
			content = m.renderFlowDetail(m.portFlows[index])
		}
	case dnsTab:
		index := m.dnsTable.Cursor()
		if m.dnsMode == currentDNSMode && index >= 0 && index < len(m.dnsEntries) {
			m.detailTitle = "DNS Record"
			m.detailDNSID = m.dnsEntries[index].ID
			content = m.renderDNSDetail(m.dnsEntries[index])
		} else if m.dnsMode == historyDNSMode && index >= 0 && index < len(m.dnsEvents) {
			m.detailTitle = "DNS Event"
			m.detailDNSEventID = m.dnsEvents[index].id
			content = m.renderDNSEventDetail(m.dnsEvents[index])
		}
	case persistenceTab:
		component := m.findingsList
		title := "Persistence Evidence"
		if m.persistenceMode == persistenceIntegrityMode {
			component = m.integrityList
			title = "Persistence Integrity Evidence"
		}
		item, ok := component.SelectedItem().(findingItem)
		if ok {
			m.detailTitle = title
			m.detailFindingID = item.ID
			content = m.renderFindingDetail(item.Finding)
		}
	case processesTab:
		index := m.processTable.Cursor()
		if index >= 0 && index < len(m.processRows) {
			process := m.processRows[index].process
			m.detailTitle = "Process Evidence"
			m.detailProcessID = process.ID
			content = m.renderProcessDetail(process)
		}
	case loaderTab:
		item, ok := m.loaderList.SelectedItem().(findingItem)
		if ok {
			m.detailTitle = "Loader Integrity Evidence"
			m.detailLoaderID = item.ID
			content = m.renderFindingDetail(item.Finding)
		}
	}
	if content == "" {
		return
	}
	m.detail.SetContent(content)
	m.detail.GotoTop()
	m.detailOpen = true
}

func (m *Model) refreshDetailContent() {
	if !m.detailOpen {
		return
	}
	offset := m.detail.YOffset
	if m.detailFlowID != "" {
		for _, item := range m.store.Active() {
			if item.ID == m.detailFlowID {
				m.detail.SetContent(m.renderFlowDetail(item))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This socket is no longer active. Its lifecycle remains in the JSONL report."))
		m.detail.GotoTop()
		return
	}
	if m.detailTrafficID != "" {
		for _, item := range m.store.History() {
			if item.ID == m.detailTrafficID {
				m.detail.SetContent(m.renderTrafficDetail(item))
				m.detail.SetYOffset(offset)
				return
			}
		}
	}
	if m.detailDNSID != "" {
		for _, entry := range m.dnsStore.Entries(time.Now()) {
			if entry.ID == m.detailDNSID {
				m.detail.SetContent(m.renderDNSDetail(entry))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This DNS record is no longer available."))
		m.detail.GotoTop()
		return
	}
	if m.detailDNSEventID != 0 {
		for index := 0; index < m.dnsHistory.len(); index++ {
			entry := m.dnsHistory.at(index)
			if entry.id == m.detailDNSEventID {
				m.detail.SetContent(m.renderDNSEventDetail(entry))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This DNS event aged out of the in-memory history. Its JSONL record remains available when recording is enabled."))
		m.detail.GotoTop()
		return
	}
	if m.detailFindingID != "" {
		for _, finding := range m.findings {
			if finding.ID == m.detailFindingID {
				m.detail.SetContent(m.renderFindingDetail(finding))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This persistence entry was not present in the latest scan."))
		m.detail.GotoTop()
		return
	}
	if m.detailProcessID != "" {
		for _, process := range m.processes {
			if process.ID == m.detailProcessID {
				m.detail.SetContent(m.renderProcessDetail(process))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This process was not present in the latest runtime scan."))
		m.detail.GotoTop()
		return
	}
	if m.detailLoaderID != "" {
		for _, finding := range m.loaderFindings {
			if finding.ID == m.detailLoaderID {
				m.detail.SetContent(m.renderFindingDetail(finding))
				m.detail.SetYOffset(offset)
				return
			}
		}
		m.detail.SetContent(m.styles.warning.Render("This loader finding was not present in the latest runtime scan."))
		m.detail.GotoTop()
	}
}

func (m Model) ShortHelp() []key.Binding {
	if m.activeTab == persistenceTab {
		filterKey := m.findingsList.KeyMap.Filter
		if m.persistenceMode == persistenceIntegrityMode {
			filterKey = m.integrityList.KeyMap.Filter
		}
		return []key.Binding{m.keys.NextTab, m.keys.Mode, m.keys.Detail, filterKey, m.keys.Refresh, m.keys.Legend, m.keys.Help, m.keys.Quit}
	}
	if m.activeTab == loaderTab {
		return []key.Binding{m.keys.NextTab, m.keys.Mode, m.keys.Trust, m.keys.Detail, m.loaderList.KeyMap.Filter, m.keys.Refresh, m.keys.Legend, m.keys.Quit}
	}
	if m.activeTab == processesTab {
		if m.processMode.flat() {
			return []key.Binding{m.keys.NextTab, m.keys.Mode, m.keys.Trust, m.keys.Sort, m.keys.Detail, m.keys.Filter, m.keys.Refresh, m.keys.Legend, m.keys.Quit}
		}
		return []key.Binding{m.keys.NextTab, m.keys.Mode, m.keys.Trust, m.keys.Detail, m.keys.Collapse, m.keys.Filter, m.keys.Refresh, m.keys.Legend, m.keys.Quit}
	}
	if isNetworkTab(m.activeTab) || m.activeTab == dnsTab {
		return []key.Binding{m.keys.NextTab, m.keys.Mode, m.keys.Detail, m.keys.Filter, m.keys.Pause, m.keys.Help, m.keys.Quit}
	}
	return []key.Binding{m.keys.NextTab, m.keys.Detail, m.keys.Filter, m.keys.Pause, m.keys.Help, m.keys.Quit}
}

func (m Model) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{m.keys.NextTab, m.keys.PreviousTab, m.keys.Inbound, m.keys.Outbound, m.keys.DNS, m.keys.Ports, m.keys.Persistence, m.keys.Processes, m.keys.Loader},
		{m.keys.Detail, m.keys.Back, m.keys.Filter, m.keys.ClearFilter, m.keys.Refresh, m.keys.Collapse},
		{m.keys.Mode, m.keys.Trust, m.keys.Sort, m.keys.Pause, m.keys.Legend, m.keys.Help, m.keys.Quit},
	}
}

func (m Model) errorText() string {
	parts := make([]string, 0, 4)
	if (isNetworkTab(m.activeTab) || m.activeTab == portsTab) && m.collectorErr != nil {
		parts = append(parts, "network: "+m.collectorErr.Error())
	}
	if m.activeTab == persistenceTab && m.scannerErr != nil {
		parts = append(parts, "persistence: "+m.scannerErr.Error())
	}
	if (m.activeTab == processesTab || m.activeTab == loaderTab) && m.runtimeScannerErr != nil {
		parts = append(parts, "runtime: "+m.runtimeScannerErr.Error())
	}
	if m.activeTab == dnsTab && m.dnsErr != nil {
		parts = append(parts, "dns: "+m.dnsErr.Error())
	}
	if m.recorderErr != nil {
		parts = append(parts, "recording: "+m.recorderErr.Error())
	}
	return fmt.Sprintf("%s", strings.Join(parts, " | "))
}

func integrityOnly(findings []persistence.Finding) []persistence.Finding {
	result := make([]persistence.Finding, 0)
	for _, finding := range findings {
		if finding.Provenance != persistence.ProvenancePackageMatch {
			result = append(result, finding)
		}
	}
	return result
}
