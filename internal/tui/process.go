package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/xhzeem/procwire/internal/persistence"
	"github.com/xhzeem/procwire/internal/runtimecheck"
)

// processMode selects how the process tab presents its inventory. Tree keeps
// the parent/child hierarchy, live is a top-style ranked sampler, and risk
// isolates the processes the scanner raised something about.
type processMode int

const (
	processTreeMode processMode = iota
	processLiveMode
	processRiskMode
	processModeCount
)

// loaderMode narrows the loader tab to one class of injection evidence.
type loaderMode int

const (
	loaderAllMode loaderMode = iota
	loaderInjectionMode
	loaderMappingMode
	loaderModeCount
)

// trustFilter is the shared integrity filter for the process and loader tabs.
type trustFilter int

const (
	trustAll trustFilter = iota
	trustSuspect
	trustWarning
	trustUnpackaged
	trustFilterCount
)

type processSort int

const (
	sortByRisk processSort = iota
	sortByCPU
	sortByMemory
	sortByPID
	sortByName
	processSortCount
)

// The risk bands split the 0-99 triage score into the five steps the RISK
// column colours. riskReview is one review-level finding on its own,
// riskWarning is one warning-level finding, and riskCritical means several
// independent conditions landed on the same process.
const (
	riskReview   = 20
	riskElevated = 40
	riskWarning  = 55
	riskCritical = 80
)

// riskBand names a score for the legend and the process detail.
func riskBand(score int) string {
	switch {
	case score >= riskCritical:
		return "critical"
	case score >= riskWarning:
		return "warning"
	case score >= riskElevated:
		return "elevated"
	case score >= riskReview:
		return "review"
	default:
		return "baseline"
	}
}

type processMetric struct {
	sampled    bool
	hasCPU     bool
	cpuPercent float64
	memPercent float64
	rssBytes   uint64
	cpuSeconds float64
	threads    int
	state      string
}

func (mode processMode) label() string {
	switch mode {
	case processLiveMode:
		return "LIVE"
	case processRiskMode:
		return "RISK"
	default:
		return "TREE"
	}
}

func (mode processMode) flat() bool { return mode != processTreeMode }

func (mode loaderMode) label() string {
	switch mode {
	case loaderInjectionMode:
		return "INJECTION"
	case loaderMappingMode:
		return "MAPPINGS"
	default:
		return "ALL"
	}
}

func (filter trustFilter) label() string {
	switch filter {
	case trustSuspect:
		return "SUSPECT"
	case trustWarning:
		return "WARNING"
	case trustUnpackaged:
		return "UNPACKAGED"
	default:
		return "ALL"
	}
}

func (order processSort) label() string {
	switch order {
	case sortByCPU:
		return "CPU"
	case sortByMemory:
		return "MEMORY"
	case sortByPID:
		return "PID"
	case sortByName:
		return "NAME"
	default:
		return "RISK"
	}
}

// riskFlags are the process flags that describe how a process is running
// rather than who owns it. Any one of them makes a process a triage candidate.
func riskFlags(process runtimecheck.Process) []string {
	raised := make([]string, 0, len(process.Flags))
	for _, flag := range process.Flags {
		switch flag {
		case runtimecheck.FlagMemfd, runtimecheck.FlagVolatile, runtimecheck.FlagDeleted,
			runtimecheck.FlagReplaced, runtimecheck.FlagWritable, runtimecheck.FlagTraced,
			runtimecheck.FlagNew:
			raised = append(raised, flag)
		}
	}
	return raised
}

// processRisk is a composite 0-100 triage score. It is an ordering aid for a
// human analyst, not a verdict: a high score means "look at this first".
func processRisk(process runtimecheck.Process) int {
	score := 0
	switch process.Level {
	case persistence.LevelWarning:
		score += 55
	case persistence.LevelReview:
		score += 25
	}
	switch process.Provenance {
	case persistence.ProvenancePackageModified:
		score += 30
	case persistence.ProvenanceLocal:
		score += 15
	case persistence.ProvenancePackageOwned, persistence.ProvenanceGenerated:
		score += 8
	case persistence.ProvenanceUnverified:
		score += 10
	}
	for _, flag := range process.Flags {
		switch flag {
		case runtimecheck.FlagMemfd:
			score += 30
		case runtimecheck.FlagVolatile:
			score += 25
		case runtimecheck.FlagDeleted, runtimecheck.FlagReplaced:
			score += 20
		case runtimecheck.FlagWritable:
			score += 15
		case runtimecheck.FlagTraced, runtimecheck.FlagNew:
			score += 10
		case runtimecheck.FlagCaps:
			score += 5
		case runtimecheck.FlagRoot:
			score += 3
		}
	}
	if process.KernelThread {
		// Kernel threads have no userspace executable to verify, so their
		// unverified provenance is expected rather than suspicious.
		return min(score, 5)
	}
	// The score is an ordinal for triage, so it saturates at two digits and
	// stays inside the narrowest RISK column.
	return min(score, 99)
}

// processSuspect reports whether the scanner raised anything about a process.
func processSuspect(process runtimecheck.Process) bool {
	if process.KernelThread {
		return process.Level == persistence.LevelWarning
	}
	return process.Level != persistence.LevelInfo || len(riskFlags(process)) > 0
}

func (filter trustFilter) matchesProcess(process runtimecheck.Process) bool {
	switch filter {
	case trustSuspect:
		return processSuspect(process)
	case trustWarning:
		return process.Level == persistence.LevelWarning
	case trustUnpackaged:
		return !process.KernelThread && process.Provenance != persistence.ProvenancePackageMatch
	default:
		return true
	}
}

func (filter trustFilter) matchesFinding(finding persistence.Finding) bool {
	switch filter {
	case trustSuspect:
		return finding.Level != persistence.LevelInfo
	case trustWarning:
		return finding.Level == persistence.LevelWarning
	case trustUnpackaged:
		return finding.Provenance != persistence.ProvenancePackageMatch
	default:
		return true
	}
}

func (mode loaderMode) matches(finding persistence.Finding) bool {
	switch mode {
	case loaderInjectionMode:
		return finding.Mechanism == "loader environment" || finding.Mechanism == "system loader preload"
	case loaderMappingMode:
		return finding.Mechanism == "executable memory mapping"
	default:
		return true
	}
}

type processCounts struct {
	total    int
	suspect  int
	warning  int
	fresh    int
	topRisk  int
	topName  string
	unpacked int
}

func countProcesses(processes []runtimecheck.Process) processCounts {
	counts := processCounts{total: len(processes)}
	for _, process := range processes {
		if processSuspect(process) {
			counts.suspect++
		}
		if process.Level == persistence.LevelWarning {
			counts.warning++
		}
		if hasFlag(process, runtimecheck.FlagNew) {
			counts.fresh++
		}
		if !process.KernelThread && process.Provenance != persistence.ProvenancePackageMatch {
			counts.unpacked++
		}
		if risk := processRisk(process); risk > counts.topRisk {
			counts.topRisk = risk
			counts.topName = fmt.Sprintf("%s(%d)", process.Name, process.PID)
		}
	}
	return counts
}

func hasFlag(process runtimecheck.Process, flag string) bool {
	for _, candidate := range process.Flags {
		if candidate == flag {
			return true
		}
	}
	return false
}

// sortProcessRows orders the flat process views. Every comparison falls back
// to PID so redraws stay stable while a sample refreshes underneath.
func (m Model) sortProcessRows(rows []processTreeRow, order processSort) {
	sort.SliceStable(rows, func(i, j int) bool {
		left, right := rows[i].process, rows[j].process
		switch order {
		case sortByCPU:
			leftCPU, rightCPU := m.metrics[left.ID].cpuPercent, m.metrics[right.ID].cpuPercent
			if leftCPU != rightCPU {
				return leftCPU > rightCPU
			}
		case sortByMemory:
			leftMemory, rightMemory := m.metrics[left.ID].rssBytes, m.metrics[right.ID].rssBytes
			if leftMemory != rightMemory {
				return leftMemory > rightMemory
			}
		case sortByName:
			if left.Name != right.Name {
				return left.Name < right.Name
			}
		case sortByPID:
		default:
			leftRisk, rightRisk := processRisk(left), processRisk(right)
			if leftRisk != rightRisk {
				return leftRisk > rightRisk
			}
			leftCPU, rightCPU := m.metrics[left.ID].cpuPercent, m.metrics[right.ID].cpuPercent
			if leftCPU != rightCPU {
				return leftCPU > rightCPU
			}
		}
		return left.PID < right.PID
	})
}

// sampledProcess synthesises an inventory entry for a process the sampler can
// see but the last integrity scan did not cover.
func sampledProcess(entry runtimecheck.ProcessSample, scanned bool) runtimecheck.Process {
	process := runtimecheck.Process{
		ID:         entry.ID(),
		PID:        entry.PID,
		PPID:       entry.PPID,
		StartTime:  entry.StartTime,
		State:      entry.State,
		Name:       entry.Name,
		User:       entry.User,
		UID:        entry.UID,
		Level:      persistence.LevelInfo,
		Provenance: persistence.ProvenanceUnverified,
	}
	if scanned {
		process.Flags = []string{runtimecheck.FlagNew}
		process.Integrity = "started after the last runtime integrity scan"
		process.Reason = "process appeared in live sampling after the last integrity scan; press r to verify it"
		return process
	}
	process.Integrity = "awaiting the first runtime integrity scan"
	process.Reason = "process is visible to live sampling; integrity evidence is still being collected"
	return process
}

func formatPercent(value float64, known bool) string {
	if !known {
		return "-"
	}
	return fmt.Sprintf("%.1f", value)
}

func formatBytes(value uint64) string {
	if value == 0 {
		return "-"
	}
	const unit = 1024.0
	size := float64(value)
	for _, suffix := range []string{"B", "K", "M", "G", "T"} {
		if size < unit || suffix == "T" {
			if size >= 100 || suffix == "B" {
				return fmt.Sprintf("%.0f%s", size, suffix)
			}
			return fmt.Sprintf("%.1f%s", size, suffix)
		}
		size /= unit
	}
	return "-"
}

func formatCPUTime(seconds float64) string {
	if seconds <= 0 {
		return "-"
	}
	return compactDuration(time.Duration(seconds * float64(time.Second)))
}

func flagsText(process runtimecheck.Process) string {
	if len(process.Flags) == 0 {
		return "-"
	}
	return strings.Join(process.Flags, ",")
}
