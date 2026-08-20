//go:build linux

package runtimecheck

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// clockTicks is the kernel USER_HZ used to convert /proc/<pid>/stat CPU ticks
// into seconds. Linux fixes it at 100 on every architecture procfs exposes to
// userspace, and reading it needs cgo, so it stays a constant here.
const clockTicks = 100

type linuxSampler struct {
	procRoot   string
	passwdPath string
	pageSize   uint64
}

func NewSampler() Sampler {
	return &linuxSampler{procRoot: "/proc", passwdPath: "/etc/passwd", pageSize: uint64(os.Getpagesize())}
}

// Sample reads only /proc/<pid>/stat for every visible process. It is meant to
// run at the polling interval so the process view stays live between the far
// more expensive integrity scans.
func (sampler *linuxSampler) Sample(ctx context.Context) (Sample, error) {
	entries, err := os.ReadDir(sampler.procRoot)
	if err != nil {
		return Sample{}, err
	}
	users := readUsers(sampler.passwdPath)
	sample := Sample{
		CapturedAt:       time.Now(),
		ClockTicks:       clockTicks,
		MemoryTotalBytes: readMemoryTotal(sampler.procRoot),
		Processes:        make([]ProcessSample, 0, len(entries)),
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return sample, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		sample.Visible++
		data, err := os.ReadFile(sampler.procRoot + "/" + entry.Name() + "/stat")
		if err != nil {
			sample.UnreadableRecords++
			continue
		}
		process, err := parseProcessSample(string(data), sampler.pageSize)
		if err != nil {
			sample.UnreadableRecords++
			continue
		}
		process.PID = pid
		if info, err := entry.Info(); err == nil {
			if native, ok := info.Sys().(*syscall.Stat_t); ok {
				process.UID = native.Uid
				process.User = userName(users, native.Uid)
			}
		}
		sample.Processes = append(sample.Processes, process)
	}
	sort.Slice(sample.Processes, func(i, j int) bool { return sample.Processes[i].PID < sample.Processes[j].PID })
	return sample, nil
}

func parseProcessSample(value string, pageSize uint64) (ProcessSample, error) {
	identity, err := parseProcStat(value)
	if err != nil {
		return ProcessSample{}, err
	}
	process := ProcessSample{
		PPID:      identity.ppid,
		StartTime: identity.startTime,
		State:     identity.state,
		Name:      identity.name,
	}
	// Fields are indexed from /proc/<pid>/stat field 3 (state) because the
	// leading pid and parenthesised command are cut by parseProcStat.
	fields := strings.Fields(value[strings.LastIndex(value, ") ")+2:])
	utime := parseUint(fields, 11)
	stime := parseUint(fields, 12)
	process.CPUTicks = utime + stime
	process.Threads = int(parseUint(fields, 17))
	process.RSSBytes = parseUint(fields, 21) * pageSize
	return process, nil
}

func parseUint(fields []string, index int) uint64 {
	if index >= len(fields) {
		return 0
	}
	value, err := strconv.ParseUint(fields[index], 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func readMemoryTotal(procRoot string) uint64 {
	data, err := readLimited(procRoot+"/meminfo", 1<<20)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, raw, found := strings.Cut(line, ":")
		if !found || key != "MemTotal" {
			continue
		}
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			return 0
		}
		kilobytes, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		return kilobytes * 1024
	}
	return 0
}
