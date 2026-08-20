//go:build linux

package runtimecheck

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseProcStatPreservesComplexName(t *testing.T) {
	fields := []string{"S", "1"}
	for len(fields) < 19 {
		fields = append(fields, "0")
	}
	fields = append(fields, "98765")
	identity, err := parseProcStat("42 (worker ) pool) " + strings.Join(fields, " "))
	if err != nil {
		t.Fatal(err)
	}
	if identity.name != "worker ) pool" || identity.state != "S" || identity.ppid != 1 || identity.startTime != 98765 {
		t.Fatalf("identity = %#v", identity)
	}
}

func TestParseProcStatus(t *testing.T) {
	status := parseProcStatus("Uid:\t1000\t1001\t1001\t1001\nCapEff:\t0000000000000400\nTracerPid:\t77\nNoNewPrivs:\t1\nSeccomp:\t2\n")
	if status.uid != 1000 || status.euid != 1001 || status.capEff != "0000000000000400" || status.tracerPID != 77 || !status.noNewPrivs || status.seccomp != 2 {
		t.Fatalf("status = %#v", status)
	}
}

func TestParseMapsLinePreservesPathAndDeletedMarker(t *testing.T) {
	mapping, ok := parseMapsLine("7f00-7f10 rwxp 00000000 08:01 123 /tmp/library with spaces.so (deleted)")
	if !ok {
		t.Fatal("mapping was not parsed")
	}
	if mapping.address != "7f00-7f10" || mapping.perms != "rwxp" || mapping.inode != 123 || mapping.path != "/tmp/library with spaces.so (deleted)" {
		t.Fatalf("mapping = %#v", mapping)
	}
}

func TestParsePreloadAndLoaderEnvironment(t *testing.T) {
	entries := parsePreload("/usr/lib/a.so:/opt/b.so # comment\nrelative.so\n")
	if fmt.Sprint(entries) != "[/usr/lib/a.so /opt/b.so relative.so]" {
		t.Fatalf("preload entries = %v", entries)
	}
	variables := parseLoaderEnvironment([]byte("PATH=/bin\x00LD_PRELOAD=/tmp/a.so\x00LD_LIBRARY_PATH=/opt/lib\x00SECRET=value\x00"))
	if len(variables) != 2 || variables[0].name != "LD_PRELOAD" || variables[1].name != "LD_LIBRARY_PATH" {
		t.Fatalf("loader variables = %#v", variables)
	}
}

func TestScannerInventoriesCurrentProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := NewScanner().Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pid := os.Getpid()
	found := false
	for _, process := range result.Processes {
		if process.PID == pid {
			found = true
			if process.ID == "" || process.Name == "" || process.Executable == "" {
				t.Fatalf("current process evidence is incomplete: %#v", process)
			}
			break
		}
	}
	if !found {
		t.Fatalf("current PID %d missing from %d processes", pid, len(result.Processes))
	}
	if result.ProcessCoverage.Collected == 0 || result.LoaderCoverage.MapsRead == 0 {
		t.Fatalf("coverage = process %#v loader %#v", result.ProcessCoverage, result.LoaderCoverage)
	}
}
