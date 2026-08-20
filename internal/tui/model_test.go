package tui

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
	"github.com/xhzeem/procwire/internal/runtimecheck"
)

func TestModelRendersNativeViewsAndDetails(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, Version: "test", HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	model = updated.(Model)
	updated, _ = model.Update(snapshotMsg{snapshot: observe.Snapshot{
		CapturedAt: time.Now(),
		Connections: []observe.Connection{{
			Network:   "tcp4",
			Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 50000},
			Remote:    observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
			State:     "ESTABLISHED",
			Direction: observe.DirectionOutbound,
			Owners:    []observe.Process{{PID: 42, Name: "client", Service: "client.service"}},
		}},
	}})
	model = updated.(Model)
	view := model.View()
	for _, expected := range []string{"PROCWIRE", "OUTBOUND", "1.1.1.1", "client"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("view does not contain %q", expected)
		}
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if !model.detailOpen || model.detailTitle != "Session Traffic" {
		t.Fatal("session traffic detail did not open")
	}
	updated, _ = model.Update(snapshotMsg{snapshot: observe.Snapshot{CapturedAt: time.Now().Add(time.Second)}})
	model = updated.(Model)
	if strings.Contains(model.View(), "no longer active") || !strings.Contains(model.View(), "Active sockets") {
		t.Fatal("session traffic disappeared after its socket closed")
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	model = updated.(Model)
	updated, _ = model.Update(scanMsg{result: persistence.Result{Findings: []persistence.Finding{{
		ID:         "systemd|example",
		Name:       "example.service",
		Unit:       "example.service",
		Mechanism:  "systemd service",
		Path:       "/usr/lib/systemd/system/example.service",
		Provenance: persistence.ProvenancePackageMatch,
	}}}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "SYSTEM") || !strings.Contains(view, "example.service") {
		t.Fatalf("persistence view missing provenance: %q", view)
	}

	updated, _ = model.Update(scanMsg{result: persistence.Result{Findings: []persistence.Finding{
		{Name: "stock.service", Provenance: persistence.ProvenancePackageMatch},
		{Name: "changed.service", Provenance: persistence.ProvenancePackageModified},
	}}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	view = model.View()
	if !strings.Contains(view, "changed.service") || strings.Contains(view, "stock.service") {
		t.Fatalf("persistence integrity mode did not isolate non-matching entries: %q", view)
	}
}

func TestProcessTabBuildsCollapsibleHierarchy(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 140, Height: 34})
	model = updated.(Model)
	updated, _ = model.Update(runtimeScanMsg{result: runtimecheck.Result{
		ScannedAt: time.Now(),
		Processes: []runtimecheck.Process{
			{ID: "1:10", PID: 1, PPID: 0, Name: "init", User: "root", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo},
			{ID: "20:20", PID: 20, PPID: 1, Name: "worker", User: "svc", Provenance: persistence.ProvenanceLocal, Level: persistence.LevelReview, Flags: []string{runtimecheck.FlagCaps}},
			{ID: "21:30", PID: 21, PPID: 20, Name: "helper", User: "svc", Provenance: persistence.ProvenancePackageModified, Level: persistence.LevelWarning},
		},
	}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)
	if len(model.processRows) != 3 || model.processRows[0].depth != 0 || model.processRows[1].depth != 1 || model.processRows[2].depth != 2 {
		t.Fatalf("process hierarchy = %#v", model.processRows)
	}
	view := model.View()
	for _, expected := range []string{"PROCESS TREE", "SYSTEM", "LOCAL", "MODIFIED", "worker", "helper"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("process tree missing %q: %q", expected, view)
		}
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeySpace})
	model = updated.(Model)
	if len(model.processRows) != 1 || !model.processRows[0].collapsed {
		t.Fatalf("root branch did not collapse: %#v", model.processRows)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeySpace})
	model = updated.(Model)
	model.processTable.SetCursor(1)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if !model.detailOpen || model.detailTitle != "Process Evidence" || !strings.Contains(model.View(), "init(1) -> worker(20)") {
		t.Fatal("process detail did not preserve ancestry")
	}
}

func TestProcessLiveModeMergesSamplesAndRanksByCPU(t *testing.T) {
	model := newTestModel(t, 150, 40)
	scannedAt := time.Now()
	updated, _ := model.Update(runtimeScanMsg{result: runtimecheck.Result{
		ScannedAt: scannedAt,
		Processes: []runtimecheck.Process{
			{ID: "1:10", PID: 1, PPID: 0, Name: "init", User: "root", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo},
			{ID: "20:20", PID: 20, PPID: 1, Name: "busy", User: "svc", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo},
		},
	}})
	model = updated.(Model)

	first := runtimecheck.Sample{
		CapturedAt: scannedAt, ClockTicks: 100, MemoryTotalBytes: 1 << 32,
		Processes: []runtimecheck.ProcessSample{
			{PID: 1, StartTime: 10, Name: "init", State: "S", CPUTicks: 5, RSSBytes: 1 << 20, Threads: 1},
			{PID: 20, StartTime: 20, Name: "busy", State: "R", CPUTicks: 100, RSSBytes: 8 << 20, Threads: 4},
		},
	}
	updated, _ = model.Update(runtimeSampleMsg{sample: first})
	model = updated.(Model)

	second := first
	second.CapturedAt = scannedAt.Add(time.Second)
	second.Processes = []runtimecheck.ProcessSample{
		{PID: 1, StartTime: 10, Name: "init", State: "S", CPUTicks: 6, RSSBytes: 1 << 20, Threads: 1},
		{PID: 20, StartTime: 20, Name: "busy", State: "R", CPUTicks: 145, RSSBytes: 8 << 20, Threads: 4},
		{PID: 99, StartTime: 900, Name: "dropper", State: "R", CPUTicks: 10, RSSBytes: 2 << 20, Threads: 1},
	}
	updated, _ = model.Update(runtimeSampleMsg{sample: second})
	model = updated.(Model)

	if len(model.processes) != 3 {
		t.Fatalf("live sample did not merge into the inventory: %#v", model.processes)
	}
	fresh := model.processes[2]
	if fresh.PID != 99 || !hasFlag(fresh, runtimecheck.FlagNew) {
		t.Fatalf("process started after the scan is not marked NEW: %#v", fresh)
	}
	if metric := model.metrics["20:20"]; !metric.hasCPU || metric.cpuPercent < 44 || metric.cpuPercent > 46 {
		t.Fatalf("CPU rate = %#v, want ~45%%", metric)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	if model.processMode != processLiveMode || model.processSort != sortByCPU {
		t.Fatalf("mode switch = %d, sort = %d", model.processMode, model.processSort)
	}
	if len(model.processRows) != 3 || model.processRows[0].process.PID != 20 {
		t.Fatalf("live rows are not ranked by CPU: %#v", model.processRows)
	}
	view := model.View()
	for _, expected := range []string{"PROCESS LIVE", "CPU%", "MEM%", "RSS", "dropper", "NEW", "45.0"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("live process view missing %q: %q", expected, view)
		}
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	model = updated.(Model)
	if model.processSort != sortByMemory || model.processRows[0].process.PID != 20 {
		t.Fatalf("memory sort did not apply: sort=%d rows=%#v", model.processSort, model.processRows)
	}
}

func TestProcessRiskModeAndTrustFilterIsolateSuspects(t *testing.T) {
	model := newTestModel(t, 140, 36)
	updated, _ := model.Update(runtimeScanMsg{result: runtimecheck.Result{
		ScannedAt: time.Now(),
		Processes: []runtimecheck.Process{
			{ID: "1:10", PID: 1, Name: "init", User: "root", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo},
			{ID: "20:20", PID: 20, PPID: 1, Name: "helper", User: "svc", Provenance: persistence.ProvenanceLocal, Level: persistence.LevelReview, Flags: []string{runtimecheck.FlagTraced}, Reason: "process is currently traced"},
			{ID: "30:30", PID: 30, PPID: 1, Name: "dropper", User: "root", Provenance: persistence.ProvenanceLocal, Level: persistence.LevelWarning, Flags: []string{runtimecheck.FlagMemfd, runtimecheck.FlagRoot}, Reason: "process executes from a memory-backed file"},
		},
	}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)

	for range 2 {
		updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
		model = updated.(Model)
	}
	if model.processMode != processRiskMode {
		t.Fatalf("process mode = %d, want risk", model.processMode)
	}
	if len(model.processRows) != 2 || model.processRows[0].process.PID != 30 {
		t.Fatalf("risk view did not isolate and rank suspects: %#v", model.processRows)
	}
	view := model.View()
	for _, expected := range []string{"PROCESS RISK", "REASON", "memory-backed", "!!"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("risk view missing %q: %q", expected, view)
		}
	}
	if strings.Contains(view, "init") {
		t.Fatalf("risk view kept a clean process: %q", view)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	model = updated.(Model)
	if model.trust != trustWarning {
		t.Fatalf("trust filter = %d, want warning", model.trust)
	}
	if len(model.processRows) != 1 || model.processRows[0].process.PID != 30 {
		t.Fatalf("warning trust filter did not narrow the view: %#v", model.processRows)
	}
	if view := model.View(); !strings.Contains(view, "TRUST WARNING") {
		t.Fatalf("active trust filter is not shown: %q", view)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	if model.processMode != processTreeMode {
		t.Fatalf("mode did not cycle back to tree: %d", model.processMode)
	}
	if len(model.processRows) != 2 || model.processRows[0].process.PID != 1 || model.processRows[1].process.PID != 30 {
		t.Fatalf("filtered tree did not keep the ancestry of the match: %#v", model.processRows)
	}
}

func TestLoaderTabModeAndTrustFilters(t *testing.T) {
	model := newTestModel(t, 130, 36)
	findings := []persistence.Finding{
		{ID: "loader|env|1", Name: "daemon: LD_PRELOAD", Mechanism: "loader environment", Level: persistence.LevelWarning, Provenance: persistence.ProvenanceLocal, Path: "/tmp/inject.so"},
		{ID: "loader|map|2", Name: "daemon: libc.so", Mechanism: "executable memory mapping", Level: persistence.LevelReview, Provenance: persistence.ProvenancePackageMatch, Path: "/usr/lib/libc.so"},
	}
	updated, _ := model.Update(runtimeScanMsg{result: runtimecheck.Result{ScannedAt: time.Now(), LoaderFindings: findings}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	model = updated.(Model)
	if len(model.loaderVisible) != 2 {
		t.Fatalf("loader tab did not start with every finding: %#v", model.loaderVisible)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	if model.loaderMode != loaderInjectionMode || len(model.loaderVisible) != 1 || model.loaderVisible[0].ID != "loader|env|1" {
		t.Fatalf("injection mode did not isolate loader controls: %#v", model.loaderVisible)
	}
	if view := model.View(); !strings.Contains(view, "LOADER INJECTION") || strings.Contains(view, "libc.so") {
		t.Fatalf("injection view is wrong: %q", view)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	if model.loaderMode != loaderMappingMode || len(model.loaderVisible) != 1 || model.loaderVisible[0].ID != "loader|map|2" {
		t.Fatalf("mapping mode did not isolate memory mappings: %#v", model.loaderVisible)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'t'}})
	model = updated.(Model)
	if model.trust != trustWarning || len(model.loaderVisible) != 1 || model.loaderVisible[0].ID != "loader|env|1" {
		t.Fatalf("loader trust filter did not narrow to warnings: %#v", model.loaderVisible)
	}
	if view := model.View(); !strings.Contains(view, "TRUST WARNING") || !strings.Contains(view, "LD_PRELOAD") {
		t.Fatalf("loader warning view is wrong: %q", view)
	}
}

func TestRuntimeSamplerFailureLeavesScanInventoryUsable(t *testing.T) {
	model := newTestModel(t, 120, 32)
	updated, _ := model.Update(runtimeScanMsg{result: runtimecheck.Result{
		ScannedAt: time.Now(),
		Processes: []runtimecheck.Process{{ID: "1:10", PID: 1, Name: "init", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo}},
	}})
	model = updated.(Model)
	updated, _ = model.Update(runtimeSampleMsg{err: runtimecheck.ErrUnsupported})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)
	if len(model.processRows) != 1 {
		t.Fatalf("scan inventory was lost when sampling failed: %#v", model.processRows)
	}
	if view := model.View(); !strings.Contains(view, "live sampling unavailable") || !strings.Contains(view, "init") {
		t.Fatalf("sampler failure is not reported alongside the inventory: %q", view)
	}
}

func TestLiveSamplingRecordsProcessChurn(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &testRecorder{}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath, Recorder: recorder})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	model = updated.(Model)

	now := time.Now()
	updated, _ = model.Update(runtimeSampleMsg{sample: runtimecheck.Sample{
		CapturedAt: now, ClockTicks: 100,
		Processes: []runtimecheck.ProcessSample{{PID: 1, StartTime: 10, Name: "init"}, {PID: 7, StartTime: 70, Name: "cron"}},
	}})
	model = updated.(Model)
	if recorder.count("process_started") != 0 {
		t.Fatal("the first sample logged the whole inventory as new processes")
	}

	updated, _ = model.Update(runtimeSampleMsg{sample: runtimecheck.Sample{
		CapturedAt: now.Add(time.Second), ClockTicks: 100,
		Processes: []runtimecheck.ProcessSample{{PID: 1, StartTime: 10, Name: "init"}, {PID: 88, StartTime: 880, Name: "curl"}},
	}})
	model = updated.(Model)
	if recorder.count("process_started") != 1 || recorder.count("process_exited") != 1 {
		t.Fatalf("churn between integrity scans was not recorded: %v", recorder.kinds)
	}
}

func TestTrustRiskAndUserColoursAreDistinct(t *testing.T) {
	styleSet := newStyles()
	key := func(style lipgloss.Style) string {
		return fmt.Sprintf("%v|%t", style.GetForeground(), style.GetBold())
	}

	seen := make(map[string]string)
	for _, label := range []string{"SYSTEM", "MODIFIED", "OWNED", "LOCAL", "GENERATED", "PENDING", "KERNEL", "UNKNOWN"} {
		colour := key(styleSet.trust(label))
		if other, duplicate := seen[colour]; duplicate {
			t.Fatalf("trust labels %q and %q share a colour", other, label)
		}
		seen[colour] = label
	}

	seen = make(map[string]string)
	for _, score := range []int{0, riskReview, riskElevated, riskWarning, riskCritical} {
		colour := key(styleSet.risk(score))
		if other, duplicate := seen[colour]; duplicate {
			t.Fatalf("risk bands %s and %s share a colour", other, riskBand(score))
		}
		seen[colour] = riskBand(score)
	}
	for _, threshold := range []int{riskReview, riskElevated, riskWarning, riskCritical} {
		if key(styleSet.risk(threshold-1)) == key(styleSet.risk(threshold)) {
			t.Fatalf("score %d does not change colour at the band boundary", threshold)
		}
	}

	if key(styleSet.user("root")) == key(styleSet.user("www-data")) {
		t.Fatal("root shares a colour with a service account")
	}
	if key(styleSet.user("deploy")) != key(styleSet.user("deploy")) {
		t.Fatal("user colours are not stable across rows")
	}
}

func TestProcessRowsCarryPerCellColour(t *testing.T) {
	profile := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	defer lipgloss.SetColorProfile(profile)

	model := newTestModel(t, 150, 32)
	updated, _ := model.Update(runtimeScanMsg{result: runtimecheck.Result{
		ScannedAt: time.Now(),
		Processes: []runtimecheck.Process{
			{ID: "1:10", PID: 1, Name: "init", User: "root", Provenance: persistence.ProvenancePackageMatch, Level: persistence.LevelInfo},
			{ID: "30:30", PID: 30, PPID: 1, Name: "dropper", User: "www-data", Provenance: persistence.ProvenanceLocal, Level: persistence.LevelWarning, Flags: []string{runtimecheck.FlagMemfd}},
		},
	}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)

	body := model.bodyView()
	styleSet := model.styles
	for name, style := range map[string]lipgloss.Style{
		"SYSTEM trust":  styleSet.trust("SYSTEM"),
		"LOCAL trust":   styleSet.trust("LOCAL"),
		"root user":     styleSet.user("root"),
		"critical risk": styleSet.risk(riskCritical),
	} {
		colour := foregroundSequence(style)
		if colour == "" || !strings.Contains(body, colour) {
			t.Fatalf("%s colour %q is not applied to the process rows", name, colour)
		}
	}
	assertViewFits(t, model)
}

// foregroundSequence extracts the SGR foreground parameters a style emits, so
// a test can look for the colour whether or not the row also carries the
// selection background.
func foregroundSequence(style lipgloss.Style) string {
	return regexp.MustCompile(`38;2;\d+;\d+;\d+`).FindString(style.Render("x"))
}

func newTestModel(t *testing.T, width, height int) Model {
	t.Helper()
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: width, Height: height})
	return updated.(Model)
}

func TestLoaderTabAndLabelLegend(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 120, Height: 34})
	model = updated.(Model)
	finding := persistence.Finding{
		ID: "loader|env|1", Name: "daemon: LD_PRELOAD", Mechanism: "loader environment",
		Level: persistence.LevelWarning, Provenance: persistence.ProvenanceLocal, Path: "/tmp/inject.so",
	}
	updated, _ = model.Update(runtimeScanMsg{result: runtimecheck.Result{ScannedAt: time.Now(), LoaderFindings: []persistence.Finding{finding}}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "daemon: LD_PRELOAD") || !strings.Contains(view, "LOCAL") {
		t.Fatalf("loader tab missing finding: %q", view)
	}
	active := model.activeTab
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	model = updated.(Model)
	view := model.View()
	for _, expected := range []string{"LABEL AND FLAG LEGEND", "SYSTEM", "MODIFIED", "DELETED", "not proven safe"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("legend missing %q: %q", expected, view)
		}
	}
	if model.activeTab != active {
		t.Fatal("legend key changed the active tab")
	}
}

func TestDNSIsIntegratedAsATab(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &testRecorder{}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath, Recorder: recorder})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	model = updated.(Model)

	query := testDNSQuery("example.com")
	client := observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 53000}
	server := observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 53}
	updated, _ = model.Update(dnsMonitorMsg{packets: []dnsmon.Packet{dnsPacket(query, client, server, observe.Process{PID: 42, Name: "client"})}})
	model = updated.(Model)

	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	updated, _ = model.Update(dnsMonitorMsg{packets: []dnsmon.Packet{dnsPacket(response, server, client, observe.Process{})}})
	model = updated.(Model)
	updated, _ = model.Update(snapshotMsg{snapshot: observe.Snapshot{
		CapturedAt: time.Now(),
		Connections: []observe.Connection{{
			Network:   "tcp4",
			Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 51000},
			Remote:    observe.Endpoint{Address: netip.MustParseAddr("1.2.3.4"), Port: 443},
			State:     "ESTABLISHED",
			Direction: observe.DirectionOutbound,
		}},
	}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "example.com:443") {
		t.Fatalf("network destination was not enriched from DNS: %q", view)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	model = updated.(Model)
	view := model.View()
	for _, expected := range []string{"3 DNS", "example.com", "1.2.3.4", "client"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("DNS tab does not contain %q: %q", expected, view)
		}
	}
	for _, expected := range []string{"TIME", "DIR", "ANSWER", "RCODE"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("DNS History header does not contain %q: %q", expected, view)
		}
	}
	if recorder.count("dns_event") != 2 {
		t.Fatalf("recorded DNS events = %d", recorder.count("dns_event"))
	}
	if len(model.dnsEvents) != 2 || len(model.dnsTable.Rows()) != 2 {
		t.Fatalf("DNS history collapsed events: events=%d rows=%d", len(model.dnsEvents), len(model.dnsTable.Rows()))
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyUp})
	model = updated.(Model)
	heldID := selectedDNSEventID(model.dnsTable, model.dnsEvents)
	updated, _ = model.Update(dnsMonitorMsg{packets: []dnsmon.Packet{dnsPacket(query, client, server, observe.Process{PID: 42, Name: "client"})}})
	model = updated.(Model)
	if model.dnsFollow || selectedDNSEventID(model.dnsTable, model.dnsEvents) != heldID || len(model.dnsEvents) != 3 {
		t.Fatal("DNS history did not preserve the selected event while new traffic arrived")
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'G'}})
	model = updated.(Model)
	if !model.dnsFollow || model.dnsTable.Cursor() != len(model.dnsEvents)-1 {
		t.Fatal("G did not resume following the newest DNS event")
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	if model.dnsMode != currentDNSMode || !strings.Contains(model.View(), "CURRENT") {
		t.Fatal("DNS current/history mode did not toggle")
	}
	for _, expected := range []string{"NAME", "ANSWERS", "CACHE"} {
		if view := model.View(); !strings.Contains(view, expected) {
			t.Fatalf("DNS Current header does not contain %q: %q", expected, view)
		}
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	if !model.detailOpen || model.detailTitle != "DNS Record" || !strings.Contains(model.View(), "QUERY PROCESS") {
		t.Fatal("DNS detail did not open with process attribution")
	}
}

func TestDNSCurrentRecordsAreAlphabetical(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	now := time.Now()
	for _, name := range []string{"z.example", "a.example"} {
		event := dnsmon.Event{
			CapturedAt: now,
			Direction:  dnsmon.DirectionResponse,
			Protocol:   "udp",
			RCode:      "NOERROR",
			Questions:  []dnsmon.Question{{Name: name, Type: "A", Class: 1}},
			Answers:    []dnsmon.Answer{{Name: name, Type: "A", Class: 1, TTL: 60, Value: "192.0.2.1", Section: "answer"}},
		}
		event = model.dnsStore.Apply(event)
		model.dnsHistory.append(event)
	}
	model.refreshDNS(now)
	model.activeTab = dnsTab
	model.dnsMode = currentDNSMode
	model.syncTables()
	if len(model.dnsEntries) != 2 || model.dnsEntries[0].Name != "a.example" || model.dnsEntries[1].Name != "z.example" {
		t.Fatalf("current DNS records are not alphabetical: %#v", model.dnsEntries)
	}
}

func TestDNSCurrentKeepsHeaderWhenCacheIsEmpty(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 120, Height: 32})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
	model = updated.(Model)
	view := model.View()
	for _, expected := range []string{"NAME", "ANSWERS", "CACHE", "no active cached answers"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("empty DNS Current view lost %q: %q", expected, view)
		}
	}
}

func TestDNSColumnsFitViewportInBothModes(t *testing.T) {
	for _, terminalWidth := range []int{62, 96, 120, 132, 160} {
		t.Run(strconv.Itoa(terminalWidth), func(t *testing.T) {
			hostsPath := filepath.Join(t.TempDir(), "hosts")
			if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			model := New(Config{Interval: time.Second, HostsPath: hostsPath})
			updated, _ := model.Update(tea.WindowSizeMsg{Width: terminalWidth, Height: 32})
			model = updated.(Model)
			model.activeTab = dnsTab
			now := time.Now()
			for index := 0; index < 40; index++ {
				name := fmt.Sprintf("event-%02d.example", index)
				event := dnsmon.Event{
					CapturedAt: now.Add(time.Duration(index) * time.Millisecond),
					Direction:  dnsmon.DirectionResponse,
					Protocol:   "udp",
					RCode:      "NOERROR",
					Questions:  []dnsmon.Question{{Name: name, Type: "A", Class: 1}},
					Answers:    []dnsmon.Answer{{Name: name, Type: "A", Class: 1, TTL: 60, Value: "192.0.2.1", Section: "answer"}},
				}
				event = model.dnsStore.Apply(event)
				model.dnsHistory.append(event)
			}
			model.refreshDNS(now)
			for _, mode := range []dnsMode{historyDNSMode, currentDNSMode} {
				model.dnsMode = mode
				model.resizeComponents()
				model.syncTables()
				for lineNumber, line := range strings.Split(model.dnsTable.View(), "\n") {
					if width := lipgloss.Width(line); width > model.contentWidth() {
						t.Fatalf("mode %d line %d width = %d, viewport = %d", mode, lineNumber+1, width, model.contentWidth())
					}
				}
				view := model.View()
				for lineNumber, line := range strings.Split(view, "\n") {
					if width := lipgloss.Width(line); width > model.width {
						t.Fatalf("mode %d screen line %d width = %d, terminal = %d", mode, lineNumber+1, width, model.width)
					}
				}
				if height := lipgloss.Height(view); height > model.height {
					t.Fatalf("mode %d rendered height = %d, terminal = %d", mode, height, model.height)
				}
				if !strings.Contains(strings.SplitN(view, "\n", 2)[0], "PROCWIRE") {
					t.Fatalf("mode %d top application header is not the first rendered line", mode)
				}
			}
		})
	}
}

func TestRuntimeTabsAndLegendFitViewport(t *testing.T) {
	for _, terminalWidth := range []int{62, 96, 120, 140} {
		t.Run(strconv.Itoa(terminalWidth), func(t *testing.T) {
			hostsPath := filepath.Join(t.TempDir(), "hosts")
			if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			model := New(Config{Interval: time.Second, HostsPath: hostsPath})
			updated, _ := model.Update(tea.WindowSizeMsg{Width: terminalWidth, Height: 36})
			model = updated.(Model)
			processes := make([]runtimecheck.Process, 0, 20)
			samples := make([]runtimecheck.ProcessSample, 0, 20)
			for index := 1; index <= 20; index++ {
				parent := index - 1
				processes = append(processes, runtimecheck.Process{
					ID: fmt.Sprintf("%d:%d", index, index*10), PID: index, PPID: parent,
					Name: fmt.Sprintf("process-%02d", index), User: "service-user", Executable: "/usr/bin/example",
					Command:    "/usr/bin/example --a-fairly-long-argument-list --that-should-be-truncated",
					Provenance: persistence.ProvenancePackageModified, Level: persistence.LevelWarning,
					Flags:  []string{runtimecheck.FlagRoot, runtimecheck.FlagCaps, runtimecheck.FlagMemfd, runtimecheck.FlagVolatile},
					Reason: "process executes from a memory-backed file; running executable is writable by other users",
				})
				samples = append(samples, runtimecheck.ProcessSample{
					PID: index, StartTime: uint64(index * 10), Name: fmt.Sprintf("process-%02d", index),
					State: "R", CPUTicks: uint64(index * 1000), RSSBytes: uint64(index) << 24, Threads: index,
				})
			}
			loader := persistence.Finding{ID: "loader|1", Name: "loader finding", Mechanism: "loader environment", Provenance: persistence.ProvenanceLocal, Level: persistence.LevelWarning}
			updated, _ = model.Update(runtimeScanMsg{result: runtimecheck.Result{ScannedAt: time.Now(), Processes: processes, LoaderFindings: []persistence.Finding{loader}}})
			model = updated.(Model)
			now := time.Now()
			for _, offset := range []time.Duration{0, time.Second} {
				updated, _ = model.Update(runtimeSampleMsg{sample: runtimecheck.Sample{
					CapturedAt: now.Add(offset), ClockTicks: 100, MemoryTotalBytes: 1 << 34, Processes: samples,
				}})
				model = updated.(Model)
			}
			model.activeTab = loaderTab
			for mode := loaderAllMode; mode < loaderModeCount; mode++ {
				model.loaderMode = mode
				model.syncLoaderList()
				for filter := trustAll; filter < trustFilterCount; filter++ {
					model.trust = filter
					model.syncLoaderList()
					model.resizeComponents()
					assertViewFits(t, model)
				}
			}
			model.loaderMode, model.trust = loaderAllMode, trustAll
			model.activeTab = processesTab
			for mode := processTreeMode; mode < processModeCount; mode++ {
				model.processMode = mode
				for order := sortByRisk; order < processSortCount; order++ {
					model.processSort = order
					for filter := trustAll; filter < trustFilterCount; filter++ {
						model.trust = filter
						model.resizeComponents()
						model.syncTables()
						assertViewFits(t, model)
					}
				}
			}
			model.processMode, model.trust = processTreeMode, trustAll
			model.resizeComponents()
			model.syncTables()
			model.legendOpen = true
			model.resizeComponents()
			assertViewFits(t, model)
		})
	}
}

func assertViewFits(t *testing.T, model Model) {
	t.Helper()
	view := model.View()
	for lineNumber, line := range strings.Split(view, "\n") {
		if width := lipgloss.Width(line); width > model.width {
			t.Fatalf("screen line %d width = %d, terminal = %d: %q", lineNumber+1, width, model.width, line)
		}
	}
	if height := lipgloss.Height(view); height > model.height {
		t.Fatalf("rendered height = %d, terminal = %d, tab = %d, legend = %t, header = %d/%d, body = %d/%d, footer = %d/%d", height, model.height, model.activeTab, model.legendOpen, lipgloss.Height(model.headerView()), maxLineWidth(model.headerView()), lipgloss.Height(model.bodyView()), maxLineWidth(model.bodyView()), lipgloss.Height(model.footerView()), maxLineWidth(model.footerView()))
	}
}

func maxLineWidth(value string) int {
	width := 0
	for _, line := range strings.Split(value, "\n") {
		width = max(width, lipgloss.Width(line))
	}
	return width
}

func TestNetworkModeToggleKeepsTableShapeAndTopLabelInSync(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 140, Height: 32})
	model = updated.(Model)
	updated, _ = model.Update(snapshotMsg{snapshot: observe.Snapshot{
		CapturedAt: time.Now(),
		Connections: []observe.Connection{{
			Network:   "tcp4",
			Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 50000},
			Remote:    observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
			State:     "ESTABLISHED",
			Direction: observe.DirectionOutbound,
		}},
	}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "OUTBOUND SESSION") {
		t.Fatalf("session label missing: %q", view)
	}

	for _, expected := range []string{"OUTBOUND LIVE", "OUTBOUND SESSION"} {
		updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'m'}})
		model = updated.(Model)
		if view := model.View(); !strings.Contains(view, expected) {
			t.Fatalf("mode label %q missing after toggle: %q", expected, view)
		}
	}
}

func TestInboundAndOutboundUseSeparateTabs(t *testing.T) {
	hostsPath := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(hostsPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	model := New(Config{Interval: time.Second, HostsPath: hostsPath})
	updated, _ := model.Update(tea.WindowSizeMsg{Width: 140, Height: 32})
	model = updated.(Model)
	updated, _ = model.Update(snapshotMsg{snapshot: observe.Snapshot{
		CapturedAt: time.Now(),
		Connections: []observe.Connection{
			{
				Network:   "tcp4",
				Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 50000},
				Remote:    observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
				State:     "ESTABLISHED",
				Direction: observe.DirectionOutbound,
			},
			{
				Network:   "tcp4",
				Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 8080},
				Remote:    observe.Endpoint{Address: netip.MustParseAddr("10.0.0.3"), Port: 52000},
				State:     "ESTABLISHED",
				Direction: observe.DirectionInbound,
			},
		},
	}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "1.1.1.1") || strings.Contains(view, "10.0.0.3:52000") {
		t.Fatalf("outbound tab mixed directions: %q", view)
	}

	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	model = updated.(Model)
	if view := model.View(); !strings.Contains(view, "INBOUND SESSION") || !strings.Contains(view, "10.0.0.3:52000") || strings.Contains(view, "1.1.1.1") {
		t.Fatalf("inbound tab mixed directions: %q", view)
	}
}

type testRecorder struct {
	kinds []string
}

func (recorder *testRecorder) Record(kind string, _ any) error {
	recorder.kinds = append(recorder.kinds, kind)
	return nil
}

func (recorder *testRecorder) count(kind string) int {
	count := 0
	for _, candidate := range recorder.kinds {
		if candidate == kind {
			count++
		}
	}
	return count
}

func testDNSQuery(name string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x5057)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	return append(query, 0, 0, 1, 0, 1)
}

func dnsPacket(payload []byte, source, destination observe.Endpoint, process observe.Process) dnsmon.Packet {
	return dnsmon.Packet{
		CapturedAt:  time.Now(),
		Protocol:    "udp",
		Source:      source,
		Destination: destination,
		Process:     process,
		Payload:     payload,
	}
}

func TestSanitizeTerminalControlSequences(t *testing.T) {
	input := "service\x1b]52;c;payload\a\rname\u202e"
	got := sanitizeTerminal(input, false)
	if strings.ContainsAny(got, "\x1b\a\r") || strings.ContainsRune(got, '\u202e') {
		t.Fatalf("unsafe controls remained in %q", got)
	}
	if !strings.Contains(got, "service") || !strings.Contains(got, "name") {
		t.Fatalf("printable evidence was removed: %q", got)
	}
}
