//go:build linux

package runtimecheck

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseProcessSampleReadsCPUAndMemory(t *testing.T) {
	// Indices are /proc/<pid>/stat fields 3 onward, because the leading pid
	// and parenthesised command are cut before the fields are split.
	fields := make([]string, 22)
	for index := range fields {
		fields[index] = "0"
	}
	fields[0] = "S"     // state
	fields[1] = "1"     // ppid
	fields[11] = "70"   // utime
	fields[12] = "30"   // stime
	fields[17] = "8"    // num_threads
	fields[19] = "9876" // starttime
	fields[21] = "512"  // rss in pages

	sample, err := parseProcessSample("42 (worker ) pool) "+strings.Join(fields, " "), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Name != "worker ) pool" || sample.State != "S" || sample.PPID != 1 || sample.StartTime != 9876 {
		t.Fatalf("identity = %#v", sample)
	}
	if sample.CPUTicks != 100 || sample.Threads != 8 || sample.RSSBytes != 512*4096 {
		t.Fatalf("metrics = %#v", sample)
	}
}

func TestSamplerSeesCurrentProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sample, err := NewSampler().Sample(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sample.ClockTicks == 0 || sample.CapturedAt.IsZero() {
		t.Fatalf("sample header = %#v", sample)
	}
	pid := os.Getpid()
	for _, entry := range sample.Processes {
		if entry.PID != pid {
			continue
		}
		if entry.RSSBytes == 0 || entry.Threads == 0 {
			t.Fatalf("current process sample is incomplete: %#v", entry)
		}
		if !strings.HasPrefix(entry.ID(), strconv.Itoa(pid)+":") {
			t.Fatalf("sample ID %q does not join with scan identities", entry.ID())
		}
		return
	}
	t.Fatalf("current PID %d missing from %d sampled processes", pid, len(sample.Processes))
}

func TestSamplerMemoryTotalIsReadable(t *testing.T) {
	if total := readMemoryTotal("/proc"); total == 0 {
		t.Fatal("MemTotal was not readable; MEM% would stay blank")
	}
}
