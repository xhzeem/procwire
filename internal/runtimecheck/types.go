package runtimecheck

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/xhzeem/procwire/internal/persistence"
)

var ErrUnsupported = errors.New("runtime integrity scanning requires Linux")

const (
	FlagRoot     = "ROOT"
	FlagCaps     = "CAPS"
	FlagDeleted  = "DELETED"
	FlagReplaced = "REPLACED"
	FlagMemfd    = "MEMFD"
	FlagVolatile = "VOLATILE"
	FlagWritable = "WRITABLE"
	FlagTraced   = "TRACED"
	FlagKernel   = "KERNEL"
	FlagNew      = "NEW"
)

type Process struct {
	ID                    string                 `json:"id"`
	PID                   int                    `json:"pid"`
	PPID                  int                    `json:"ppid"`
	StartTime             uint64                 `json:"start_time_ticks"`
	State                 string                 `json:"state,omitempty"`
	Name                  string                 `json:"name,omitempty"`
	User                  string                 `json:"user,omitempty"`
	UID                   uint32                 `json:"uid"`
	EffectiveUID          uint32                 `json:"effective_uid"`
	Executable            string                 `json:"executable,omitempty"`
	ExecutableTarget      string                 `json:"executable_target,omitempty"`
	Command               string                 `json:"command,omitempty"`
	Service               string                 `json:"service,omitempty"`
	RootContext           string                 `json:"root_context,omitempty"`
	Provenance            persistence.Provenance `json:"provenance"`
	Package               string                 `json:"package,omitempty"`
	PackageManager        string                 `json:"package_manager,omitempty"`
	Integrity             string                 `json:"integrity,omitempty"`
	Level                 persistence.Level      `json:"level"`
	Flags                 []string               `json:"flags,omitempty"`
	Reason                string                 `json:"reason"`
	EffectiveCapabilities string                 `json:"effective_capabilities,omitempty"`
	TracerPID             int                    `json:"tracer_pid,omitempty"`
	NoNewPrivs            bool                   `json:"no_new_privs,omitempty"`
	Seccomp               int                    `json:"seccomp,omitempty"`
	ExecutableMode        string                 `json:"executable_mode,omitempty"`
	ExecutableUID         uint32                 `json:"executable_uid,omitempty"`
	ExecutableGID         uint32                 `json:"executable_gid,omitempty"`
	KernelThread          bool                   `json:"kernel_thread,omitempty"`
}

type ProcessCoverage struct {
	Visible             int `json:"visible"`
	Collected           int `json:"collected"`
	ExitedDuringScan    int `json:"exited_during_scan"`
	PermissionDenied    int `json:"permission_denied"`
	ExecutablesVerified int `json:"executables_verified"`
}

type LoaderCoverage struct {
	ProcessesExamined int `json:"processes_examined"`
	MapsRead          int `json:"maps_read"`
	EnvironmentsRead  int `json:"environments_read"`
	MappingsChecked   int `json:"mappings_checked"`
	PermissionDenied  int `json:"permission_denied"`
}

type Result struct {
	ScannedAt       time.Time             `json:"scanned_at"`
	PackageManager  string                `json:"package_manager,omitempty"`
	Processes       []Process             `json:"processes"`
	LoaderFindings  []persistence.Finding `json:"loader_findings"`
	ProcessCoverage ProcessCoverage       `json:"process_coverage"`
	LoaderCoverage  LoaderCoverage        `json:"loader_coverage"`
	Warnings        []string              `json:"warnings,omitempty"`
}

type Scanner interface {
	Scan(context.Context) (Result, error)
}

// ProcessSample is one cheap procfs reading of a live process. It carries no
// package provenance: sampling only reads /proc/<pid>/stat so that it can run
// at the polling interval without the cost of a full integrity scan.
type ProcessSample struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	StartTime uint64 `json:"start_time_ticks"`
	State     string `json:"state,omitempty"`
	Name      string `json:"name,omitempty"`
	UID       uint32 `json:"uid"`
	User      string `json:"user,omitempty"`
	CPUTicks  uint64 `json:"cpu_ticks"`
	RSSBytes  uint64 `json:"rss_bytes"`
	Threads   int    `json:"threads"`
}

// ID matches Process.ID so a sample can be joined with the last integrity scan.
func (sample ProcessSample) ID() string {
	return fmt.Sprintf("%d:%d", sample.PID, sample.StartTime)
}

type Sample struct {
	CapturedAt        time.Time       `json:"captured_at"`
	ClockTicks        uint64          `json:"clock_ticks"`
	MemoryTotalBytes  uint64          `json:"memory_total_bytes,omitempty"`
	Processes         []ProcessSample `json:"processes"`
	Visible           int             `json:"visible"`
	UnreadableRecords int             `json:"unreadable_records,omitempty"`
}

type Sampler interface {
	Sample(context.Context) (Sample, error)
}
