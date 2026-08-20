package main

import (
	"bufio"
	"debug/elf"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xhzeem/procwire/integration/fixture"
	"github.com/xhzeem/procwire/internal/dnsmon"
	"github.com/xhzeem/procwire/internal/flow"
	"github.com/xhzeem/procwire/internal/observe"
	"github.com/xhzeem/procwire/internal/persistence"
	"github.com/xhzeem/procwire/internal/runtimecheck"
)

type record struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type observations struct {
	tcpListeners        map[uint16]bool
	udpListeners        map[uint16]bool
	attributedTCP       map[uint16]bool
	dnsQueries          map[string]bool
	dnsResponses        map[string]bool
	services            map[string]bool
	timers              map[string]bool
	cron                map[string]bool
	inbound             bool
	outbound            bool
	dnsSocket           bool
	attributedDNSSocket bool
	dnsEBPFActive       bool
	closedFlow          bool
	repeatedObservation bool
	modifiedPackageFile bool
	processInventory    bool
	liveSampling        bool
	loaderOverride      bool
	sessionEnd          bool
}

func main() {
	reportPath := flag.String("report", "", "ProcWire JSONL report")
	binaryPath := flag.String("binary", "", "ProcWire Linux ELF binary")
	manifestPath := flag.String("manifest", "", "generated integration fixture manifest")
	flag.Parse()
	if *reportPath == "" || *binaryPath == "" || *manifestPath == "" {
		fmt.Fprintln(os.Stderr, "verify: --report, --binary, and --manifest are required")
		os.Exit(2)
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	if err := verifyStaticELF(*binaryPath); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
	if err := verify(*reportPath, manifest); err != nil {
		fmt.Fprintln(os.Stderr, "verify:", err)
		os.Exit(1)
	}
}

func readManifest(path string) (fixture.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fixture.Manifest{}, fmt.Errorf("read fixture manifest: %w", err)
	}
	var manifest fixture.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fixture.Manifest{}, fmt.Errorf("decode fixture manifest: %w", err)
	}
	if manifest.ProcessName == "" || len(manifest.TCPPorts) == 0 || len(manifest.UDPPorts) == 0 || len(manifest.DNSNames) == 0 {
		return fixture.Manifest{}, fmt.Errorf("fixture manifest is incomplete: %#v", manifest)
	}
	return manifest, nil
}

func verify(path string, manifest fixture.Manifest) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	seen := newObservations(manifest)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var item record
		if err := json.Unmarshal(scanner.Bytes(), &item); err != nil {
			return fmt.Errorf("decode JSONL: %w", err)
		}
		switch item.Type {
		case "session_end":
			seen.sessionEnd = true
		case "dns_monitor_status":
			var status struct {
				Active bool `json:"active"`
			}
			if err := json.Unmarshal(item.Data, &status); err != nil {
				return fmt.Errorf("decode DNS monitor status: %w", err)
			}
			seen.dnsEBPFActive = seen.dnsEBPFActive || status.Active
		case "dns_event":
			if err := observeDNS(item.Data, manifest, seen); err != nil {
				return err
			}
		case "persistence_scan":
			if err := observePersistence(item.Data, manifest, seen); err != nil {
				return err
			}
		case "process_observation":
			var process runtimecheck.Process
			if err := json.Unmarshal(item.Data, &process); err != nil {
				return fmt.Errorf("decode process observation: %w", err)
			}
			if process.Name == manifest.ProcessName && process.PID > 0 && process.PPID > 0 && process.ID != "" {
				seen.processInventory = true
			}
		case "runtime_sample_status":
			var status struct {
				Active  bool `json:"active"`
				Sampled int  `json:"sampled"`
			}
			if err := json.Unmarshal(item.Data, &status); err != nil {
				return fmt.Errorf("decode runtime sample status: %w", err)
			}
			seen.liveSampling = seen.liveSampling || status.Active && status.Sampled > 0
		case "loader_finding":
			var finding persistence.Finding
			if err := json.Unmarshal(item.Data, &finding); err != nil {
				return fmt.Errorf("decode loader finding: %w", err)
			}
			if finding.Mechanism == "loader environment" && strings.Contains(finding.Name, manifest.ProcessName) && strings.Contains(finding.Name, "LD_LIBRARY_PATH") {
				seen.loaderOverride = true
			}
		case string(flow.EventOpened), string(flow.EventClosed):
			if err := observeFlow(item, manifest, seen); err != nil {
				return err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	checks := map[string]bool{
		"all generated TCP listeners":    allTrue(seen.tcpListeners),
		"all generated UDP listeners":    allTrue(seen.udpListeners),
		"attributed generated listeners": allTrue(seen.attributedTCP),
		"generated inbound connections":  seen.inbound,
		"generated outbound connections": seen.outbound,
		"DNS-targeted socket":            seen.dnsSocket,
		"attributed DNS-targeted socket": seen.attributedDNSSocket,
		"DNS eBPF active":                seen.dnsEBPFActive,
		"all generated DNS queries":      allTrue(seen.dnsQueries),
		"all generated DNS responses":    allTrue(seen.dnsResponses),
		"flow closures":                  seen.closedFlow,
		"repeated observations":          seen.repeatedObservation,
		"all generated service fixtures": allTrue(seen.services),
		"all generated timer fixtures":   allTrue(seen.timers),
		"all generated cron fixtures":    allTrue(seen.cron),
		"modified package-owned fixture": seen.modifiedPackageFile,
		"process hierarchy inventory":    seen.processInventory,
		"live process sampling":          seen.liveSampling,
		"loader environment override":    seen.loaderOverride,
		"clean session end":              seen.sessionEnd,
	}
	missing := make([]string, 0)
	for name, passed := range checks {
		if !passed {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("missing expected observations: %v", missing)
	}
	fmt.Printf("verified %d dynamic traffic, DNS, persistence, and lifecycle checks in %s\n", len(checks), path)
	return nil
}

func newObservations(manifest fixture.Manifest) *observations {
	seen := &observations{
		tcpListeners:  make(map[uint16]bool, len(manifest.TCPPorts)),
		udpListeners:  make(map[uint16]bool, len(manifest.UDPPorts)),
		attributedTCP: make(map[uint16]bool, len(manifest.TCPPorts)),
		dnsQueries:    make(map[string]bool, len(manifest.DNSNames)),
		dnsResponses:  make(map[string]bool, len(manifest.DNSNames)),
		services:      make(map[string]bool, len(manifest.ServiceUnits)),
		timers:        make(map[string]bool, len(manifest.TimerUnits)),
		cron:          make(map[string]bool, len(manifest.CronPaths)),
	}
	for _, port := range manifest.TCPPorts {
		seen.tcpListeners[port] = false
		seen.attributedTCP[port] = false
	}
	for _, port := range manifest.UDPPorts {
		seen.udpListeners[port] = false
	}
	for _, name := range manifest.DNSNames {
		seen.dnsQueries[name] = false
		seen.dnsResponses[name] = false
	}
	for _, unit := range manifest.ServiceUnits {
		seen.services[unit] = false
	}
	for _, unit := range manifest.TimerUnits {
		seen.timers[unit] = false
	}
	for _, path := range manifest.CronPaths {
		seen.cron[path] = false
	}
	return seen
}

func observeDNS(data json.RawMessage, manifest fixture.Manifest, seen *observations) error {
	var event dnsmon.Event
	if err := json.Unmarshal(data, &event); err != nil {
		return fmt.Errorf("decode DNS event: %w", err)
	}
	if event.Process.Name != manifest.ProcessName || event.Process.PID <= 0 {
		return nil
	}
	for _, question := range event.Questions {
		if _, expected := seen.dnsQueries[question.Name]; !expected || question.Type != "A" {
			continue
		}
		switch event.Direction {
		case dnsmon.DirectionQuery:
			seen.dnsQueries[question.Name] = true
		case dnsmon.DirectionResponse:
			if len(event.Answers) > 0 {
				seen.dnsResponses[question.Name] = true
			}
		}
	}
	return nil
}

func observePersistence(data json.RawMessage, manifest fixture.Manifest, seen *observations) error {
	var result persistence.Result
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("decode persistence result: %w", err)
	}
	for _, finding := range result.Findings {
		if _, expected := seen.services[finding.Unit]; expected && finding.Provenance == persistence.ProvenanceLocal {
			seen.services[finding.Unit] = true
		}
		if _, expected := seen.timers[finding.Unit]; expected && finding.Provenance == persistence.ProvenanceLocal {
			seen.timers[finding.Unit] = true
		}
		if _, expected := seen.cron[finding.Path]; expected && finding.Provenance == persistence.ProvenanceLocal {
			seen.cron[finding.Path] = true
		}
		if manifest.ModifiedPackageFile != "" &&
			(finding.Path == manifest.ModifiedPackageFile || finding.ResolvedPath == manifest.ModifiedPackageFile) &&
			finding.Provenance == persistence.ProvenancePackageModified {
			seen.modifiedPackageFile = true
		}
	}
	return nil
}

func observeFlow(item record, manifest fixture.Manifest, seen *observations) error {
	var event flow.Event
	if err := json.Unmarshal(item.Data, &event); err != nil {
		return fmt.Errorf("decode flow event: %w", err)
	}
	connection := event.Flow.Connection
	owned := false
	for _, owner := range connection.Owners {
		if owner.Name == manifest.ProcessName && owner.PID > 0 {
			owned = true
			break
		}
	}
	generated := expectedPort(manifest, connection.Local.Port) || expectedPort(manifest, connection.Remote.Port) || connection.Remote.Port == 53
	if item.Type == string(flow.EventClosed) {
		if generated {
			seen.closedFlow = true
			if event.Flow.Observations > 1 {
				seen.repeatedObservation = true
			}
		}
		return nil
	}
	if _, expected := seen.tcpListeners[connection.Local.Port]; expected && connection.Direction == observe.DirectionListen {
		seen.tcpListeners[connection.Local.Port] = true
		if owned {
			seen.attributedTCP[connection.Local.Port] = true
		}
	}
	if _, expected := seen.udpListeners[connection.Local.Port]; expected && connection.Direction == observe.DirectionBound {
		seen.udpListeners[connection.Local.Port] = true
	}
	if _, expected := seen.tcpListeners[connection.Local.Port]; expected && connection.Direction == observe.DirectionInbound {
		seen.inbound = true
	}
	if _, expected := seen.tcpListeners[connection.Remote.Port]; expected && connection.Direction == observe.DirectionOutbound {
		seen.outbound = true
	}
	if connection.Remote.Port == 53 {
		seen.dnsSocket = true
		if owned {
			seen.attributedDNSSocket = true
		}
	}
	return nil
}

func expectedPort(manifest fixture.Manifest, port uint16) bool {
	for _, expected := range manifest.TCPPorts {
		if expected == port {
			return true
		}
	}
	for _, expected := range manifest.UDPPorts {
		if expected == port {
			return true
		}
	}
	return false
}

func allTrue[K comparable](values map[K]bool) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}

func verifyStaticELF(path string) error {
	binary, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("open Linux ELF: %w", err)
	}
	defer binary.Close()
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			return fmt.Errorf("%s contains a dynamic interpreter and is not fully static", path)
		}
	}
	return nil
}
