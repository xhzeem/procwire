package tui

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
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
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = updated.(Model)
	view = model.View()
	if !strings.Contains(view, "changed.service") || strings.Contains(view, "stock.service") {
		t.Fatalf("integrity view did not isolate non-matching entries: %q", view)
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
