//go:build linux

package runtimecheck

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xhzeem/procwire/internal/persistence"
)

const (
	maxProcValueSize  = 4 << 20
	maxLoaderFindings = 20_000
	maxPackageRoots   = 32
)

type linuxScanner struct {
	procRoot   string
	root       string
	passwdPath string
}

type procIdentity struct {
	name      string
	state     string
	ppid      int
	startTime uint64
}

type procStatus struct {
	uid        uint32
	euid       uint32
	capEff     string
	tracerPID  int
	noNewPrivs bool
	seccomp    int
}

type mappedObject struct {
	address string
	perms   string
	inode   uint64
	path    string
}

type rootVerifier struct {
	key      string
	root     string
	verifier persistence.FileVerifier
	users    map[uint32]string
}

type unavailableVerifier struct {
	detail string
}

func (verifier unavailableVerifier) Name() string { return "unverified" }

func (verifier unavailableVerifier) Verify(path string) persistence.FileEvidence {
	return persistence.FileEvidence{Path: path, Provenance: persistence.ProvenanceUnverified, PackageManager: verifier.Name(), Integrity: verifier.detail}
}

func (verifier unavailableVerifier) VerifyContent(path string, _ io.Reader) persistence.FileEvidence {
	return verifier.Verify(path)
}

func NewScanner() Scanner {
	return &linuxScanner{procRoot: "/proc", root: "/", passwdPath: "/etc/passwd"}
}

func (scanner *linuxScanner) Scan(ctx context.Context) (Result, error) {
	result := Result{ScannedAt: time.Now()}
	verifier, warnings := persistence.NewFileVerifier(scanner.root)
	result.PackageManager = verifier.Name()
	result.Warnings = append(result.Warnings, warnings...)
	users := readUsers(scanner.passwdPath)
	entries, err := os.ReadDir(scanner.procRoot)
	if err != nil {
		return result, fmt.Errorf("list procfs processes: %w", err)
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	result.ProcessCoverage.Visible = len(pids)
	mappingCache := make(map[string]persistence.FileEvidence)
	rootVerifiers := make(map[string]rootVerifier)
	selfKey, err := processRootKey(scanner.procRoot, os.Getpid())
	if err != nil {
		selfKey = "scanner-root"
	}
	rootVerifiers[selfKey] = rootVerifier{key: selfKey, root: scanner.root, verifier: verifier, users: users}
	preloadScanned := map[string]bool{selfKey: true}
	if preload, warning := scanSystemPreload(scanner.root, selfKey, verifier); preload != nil {
		result.LoaderFindings = append(result.LoaderFindings, *preload)
	} else if warning != "" {
		result.Warnings = append(result.Warnings, warning)
	}

	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		rootKey, rootErr := processRootKey(scanner.procRoot, pid)
		if rootErr != nil {
			rootKey = fmt.Sprintf("unreadable:%d", pid)
		}
		rootState, found := rootVerifiers[rootKey]
		if !found {
			rootPath := filepath.Join(scanner.procRoot, strconv.Itoa(pid), "root")
			rootState = rootVerifier{key: rootKey, root: rootPath, users: readUsers(filepath.Join(rootPath, "etc/passwd"))}
			if len(rootVerifiers) >= maxPackageRoots {
				rootState.verifier = unavailableVerifier{detail: "process root limit reached; package provenance was not checked"}
			} else if rootErr != nil {
				rootState.verifier = unavailableVerifier{detail: "process root was not readable; package provenance was not checked"}
			} else {
				loaded, rootWarnings := persistence.NewFileVerifier(rootPath)
				rootState.verifier = loaded
				for _, warning := range rootWarnings {
					result.Warnings = append(result.Warnings, "process root "+rootKey+": "+warning)
				}
			}
			rootVerifiers[rootKey] = rootState
		}
		if !preloadScanned[rootKey] && rootErr == nil {
			preloadScanned[rootKey] = true
			if preload, warning := scanSystemPreload(rootState.root, rootKey, rootState.verifier); preload != nil {
				result.LoaderFindings = append(result.LoaderFindings, *preload)
			} else if warning != "" {
				result.Warnings = append(result.Warnings, warning)
			}
		}
		process, state, err := scanner.scanProcess(pid, rootState.users, rootKey, rootState.verifier)
		if err != nil {
			switch {
			case errors.Is(err, os.ErrNotExist):
				result.ProcessCoverage.ExitedDuringScan++
			case errors.Is(err, os.ErrPermission):
				result.ProcessCoverage.PermissionDenied++
			}
			continue
		}
		if state == "unstable" {
			result.ProcessCoverage.ExitedDuringScan++
			continue
		}
		result.Processes = append(result.Processes, process)
		result.ProcessCoverage.Collected++
		if process.Executable != "" && process.Provenance != persistence.ProvenanceUnverified {
			result.ProcessCoverage.ExecutablesVerified++
		}
		findings, coverage := scanner.scanLoaderProcess(process, rootState.verifier, mappingCache)
		result.LoaderCoverage.ProcessesExamined++
		result.LoaderCoverage.MapsRead += coverage.MapsRead
		result.LoaderCoverage.EnvironmentsRead += coverage.EnvironmentsRead
		result.LoaderCoverage.MappingsChecked += coverage.MappingsChecked
		result.LoaderCoverage.PermissionDenied += coverage.PermissionDenied
		remaining := maxLoaderFindings - len(result.LoaderFindings)
		if remaining > 0 {
			result.LoaderFindings = append(result.LoaderFindings, findings[:min(len(findings), remaining)]...)
		}
	}
	if result.ProcessCoverage.PermissionDenied > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("process inventory is partial: %d process records were not readable", result.ProcessCoverage.PermissionDenied))
	}
	if result.LoaderCoverage.PermissionDenied > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("loader visibility is partial: %d procfs maps or environment files were not readable", result.LoaderCoverage.PermissionDenied))
	}
	if len(result.LoaderFindings) == maxLoaderFindings {
		result.Warnings = append(result.Warnings, fmt.Sprintf("loader findings were limited to %d entries", maxLoaderFindings))
	}
	sort.Slice(result.LoaderFindings, func(i, j int) bool {
		left, right := levelRank(result.LoaderFindings[i].Level), levelRank(result.LoaderFindings[j].Level)
		if left != right {
			return left > right
		}
		return result.LoaderFindings[i].ID < result.LoaderFindings[j].ID
	})
	return result, nil
}

func (scanner *linuxScanner) scanProcess(pid int, users map[uint32]string, rootContext string, verifier persistence.FileVerifier) (Process, string, error) {
	root := filepath.Join(scanner.procRoot, strconv.Itoa(pid))
	beforeData, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return Process{}, "", err
	}
	before, err := parseProcStat(string(beforeData))
	if err != nil {
		return Process{}, "", err
	}
	statusData, statusErr := os.ReadFile(filepath.Join(root, "status"))
	if statusErr != nil && !errors.Is(statusErr, os.ErrNotExist) {
		return Process{}, "", statusErr
	}
	status := parseProcStatus(string(statusData))
	process := Process{
		ID:                    fmt.Sprintf("%d:%d", pid, before.startTime),
		PID:                   pid,
		PPID:                  before.ppid,
		StartTime:             before.startTime,
		State:                 before.state,
		Name:                  before.name,
		UID:                   status.uid,
		EffectiveUID:          status.euid,
		User:                  userName(users, status.euid),
		Level:                 persistence.LevelInfo,
		Provenance:            persistence.ProvenanceUnverified,
		EffectiveCapabilities: status.capEff,
		TracerPID:             status.tracerPID,
		NoNewPrivs:            status.noNewPrivs,
		Seccomp:               status.seccomp,
		RootContext:           rootContext,
	}
	if data, err := readLimited(filepath.Join(root, "comm"), 1<<20); err == nil {
		if name := strings.TrimSpace(string(data)); name != "" {
			process.Name = name
		}
	}
	if data, err := readLimited(filepath.Join(root, "cmdline"), maxProcValueSize); err == nil {
		process.Command = strings.TrimSpace(strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " "))
	}
	if data, err := readLimited(filepath.Join(root, "cgroup"), 1<<20); err == nil {
		process.Service = serviceFromCgroup(string(data))
	}

	var reasons []string
	if status.euid == 0 {
		process.Flags = append(process.Flags, FlagRoot)
	}
	if nonzeroHex(status.capEff) {
		process.Flags = append(process.Flags, FlagCaps)
	}
	if status.tracerPID > 0 {
		process.Flags = append(process.Flags, FlagTraced)
		process.Level = maxLevel(process.Level, persistence.LevelReview)
		reasons = append(reasons, fmt.Sprintf("process is currently traced by PID %d", status.tracerPID))
	}

	target, linkErr := os.Readlink(filepath.Join(root, "exe"))
	process.ExecutableTarget = target
	deleted := strings.HasSuffix(target, " (deleted)")
	process.Executable = strings.TrimSuffix(target, " (deleted)")
	process.KernelThread = process.Executable == "" && process.Command == ""
	if process.KernelThread {
		process.Flags = append(process.Flags, FlagKernel)
		process.Integrity = "kernel thread or process without a readable userspace executable"
	}
	if linkErr == nil {
		file, openErr := os.Open(filepath.Join(root, "exe"))
		if openErr == nil {
			info, statErr := file.Stat()
			if statErr == nil {
				process.ExecutableMode = info.Mode().String()
				if native, ok := info.Sys().(*syscall.Stat_t); ok {
					process.ExecutableUID = native.Uid
					process.ExecutableGID = native.Gid
				}
				if info.Mode().Perm()&0o002 != 0 {
					process.Flags = append(process.Flags, FlagWritable)
					process.Level = maxLevel(process.Level, persistence.LevelWarning)
					reasons = append(reasons, "running executable is writable by other users")
				} else if info.Mode().Perm()&0o020 != 0 {
					process.Flags = append(process.Flags, FlagWritable)
					process.Level = maxLevel(process.Level, persistence.LevelReview)
					reasons = append(reasons, "running executable is group-writable")
				}
				if filepath.IsAbs(process.Executable) && !isMemfd(process.Executable) {
					evidence := verifier.VerifyContent(process.Executable, file)
					applyProcessEvidence(&process, evidence, &reasons)
					path := filepath.Join(root, "root", strings.TrimPrefix(process.Executable, "/"))
					if current, err := os.Stat(path); err != nil || !os.SameFile(info, current) {
						process.Flags = appendUnique(process.Flags, FlagReplaced)
						process.Level = maxLevel(process.Level, persistence.LevelReview)
						reasons = append(reasons, "current executable pathname does not resolve to the running inode")
					}
				}
			}
			_ = file.Close()
		}
	}
	if deleted {
		process.Flags = appendUnique(process.Flags, FlagDeleted)
		process.Level = maxLevel(process.Level, persistence.LevelReview)
		reasons = append(reasons, "running executable has been unlinked")
	}
	if isMemfd(process.ExecutableTarget) {
		process.Flags = appendUnique(process.Flags, FlagMemfd)
		process.Level = maxLevel(process.Level, persistence.LevelWarning)
		reasons = append(reasons, "process executes from a memory-backed file")
	}
	if isVolatilePath(process.Executable) {
		process.Flags = appendUnique(process.Flags, FlagVolatile)
		process.Level = maxLevel(process.Level, persistence.LevelWarning)
		reasons = append(reasons, "process executes from a temporary writable location")
	}
	if process.Integrity != "" {
		reasons = append([]string{process.Integrity}, reasons...)
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "process was inventoried without a high-signal runtime integrity condition")
	}
	process.Reason = strings.Join(compactStrings(reasons), "; ")

	afterData, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return Process{}, "", err
	}
	after, err := parseProcStat(string(afterData))
	if err != nil || after.startTime != before.startTime {
		return Process{}, "unstable", nil
	}
	return process, "stable", nil
}

func applyProcessEvidence(process *Process, evidence persistence.FileEvidence, reasons *[]string) {
	process.Provenance = evidence.Provenance
	process.Package = evidence.Package
	process.PackageManager = evidence.PackageManager
	process.Integrity = evidence.Integrity
	switch evidence.Provenance {
	case persistence.ProvenancePackageModified:
		process.Level = maxLevel(process.Level, persistence.LevelWarning)
	case persistence.ProvenanceLocal:
		process.Level = maxLevel(process.Level, persistence.LevelReview)
		*reasons = append(*reasons, "running executable is not owned by the local package manifest")
	case persistence.ProvenancePackageOwned:
		process.Level = maxLevel(process.Level, persistence.LevelReview)
		*reasons = append(*reasons, "package owns the executable but provides no usable digest")
	}
}

func scanSystemPreload(root, rootContext string, verifier persistence.FileVerifier) (*persistence.Finding, string) {
	path := filepath.Join(root, "etc/ld.so.preload")
	data, err := readLimited(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		return nil, "cannot inspect /etc/ld.so.preload: " + err.Error()
	}
	entries := parsePreload(string(data))
	if len(entries) == 0 {
		return nil, ""
	}
	evidence := verifier.Verify("/etc/ld.so.preload")
	references := make([]persistence.FileEvidence, 0, len(entries))
	for _, entry := range entries {
		if filepath.IsAbs(entry) {
			references = append(references, verifier.Verify(entry))
		}
	}
	return &persistence.Finding{
		ID:              "loader|system-preload|" + rootContext,
		Level:           persistence.LevelWarning,
		Mechanism:       "system loader preload",
		Name:            "ld.so.preload",
		Path:            "/etc/ld.so.preload",
		User:            "all dynamic processes",
		Command:         strings.Join(entries, " "),
		Source:          "system loader configuration",
		Scope:           "root " + rootContext,
		Role:            "preload control",
		Enablement:      "active entries",
		Provenance:      evidence.Provenance,
		Package:         evidence.Package,
		PackageManager:  evidence.PackageManager,
		Integrity:       evidence.Integrity,
		ReferencedFiles: references,
		Reason:          "the dynamic loader is configured to inject shared objects into processes system-wide",
		Recommendation:  "Confirm every preload entry and compare it with an independently trusted package source.",
	}, ""
}

func (scanner *linuxScanner) scanLoaderProcess(process Process, verifier persistence.FileVerifier, cache map[string]persistence.FileEvidence) ([]persistence.Finding, LoaderCoverage) {
	root := filepath.Join(scanner.procRoot, strconv.Itoa(process.PID))
	coverage := LoaderCoverage{}
	findings := make([]persistence.Finding, 0)
	if data, err := readLimited(filepath.Join(root, "environ"), maxProcValueSize); err == nil {
		coverage.EnvironmentsRead++
		for _, variable := range parseLoaderEnvironment(data) {
			level := persistence.LevelReview
			if variable.name == "LD_PRELOAD" || variable.name == "LD_AUDIT" {
				level = persistence.LevelWarning
			}
			finding := persistence.Finding{
				ID:             fmt.Sprintf("loader|env|%s|%s", process.ID, variable.name),
				Level:          level,
				Mechanism:      "loader environment",
				Name:           fmt.Sprintf("%s (%d): %s", process.Name, process.PID, variable.name),
				Path:           fmt.Sprintf("/proc/%d/environ", process.PID),
				User:           process.User,
				Command:        variable.value,
				Source:         "process initial environment",
				Scope:          "process",
				Unit:           process.Service,
				Role:           "loader override",
				Enablement:     "present",
				Provenance:     persistence.ProvenanceUnverified,
				Reason:         variable.name + " can alter dynamic-loader behavior; presence does not prove that the value was effective",
				Recommendation: "Confirm the variable is expected and verify every referenced shared object.",
			}
			if variable.name == "LD_PRELOAD" || variable.name == "LD_AUDIT" {
				for _, value := range splitLoaderPaths(variable.value) {
					if filepath.IsAbs(value) {
						finding.ReferencedFiles = append(finding.ReferencedFiles, verifier.Verify(value))
					}
				}
			}
			findings = append(findings, finding)
		}
	} else if errors.Is(err, os.ErrPermission) {
		coverage.PermissionDenied++
	}

	file, err := os.Open(filepath.Join(root, "maps"))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			coverage.PermissionDenied++
		}
		return findings, coverage
	}
	defer file.Close()
	coverage.MapsRead++
	seen := make(map[string]struct{})
	scan := bufio.NewScanner(file)
	scan.Buffer(make([]byte, 64*1024), 4<<20)
	for scan.Scan() {
		mapping, ok := parseMapsLine(scan.Text())
		if !ok || !strings.Contains(mapping.perms, "x") {
			continue
		}
		key := fmt.Sprintf("%d|%s|%s", mapping.inode, mapping.path, mapping.perms)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		coverage.MappingsChecked++
		if finding, ok := loaderMappingFinding(process, mapping, verifier, cache); ok {
			findings = append(findings, finding)
		}
	}
	return findings, coverage
}

func loaderMappingFinding(process Process, mapping mappedObject, verifier persistence.FileVerifier, cache map[string]persistence.FileEvidence) (persistence.Finding, bool) {
	path := strings.TrimSuffix(mapping.path, " (deleted)")
	deleted := strings.HasSuffix(mapping.path, " (deleted)")
	level := persistence.LevelInfo
	reasons := make([]string, 0)
	evidence := persistence.FileEvidence{Path: path, Provenance: persistence.ProvenanceUnverified, Integrity: "mapped content was not package-verified"}
	if strings.Contains(mapping.perms, "w") {
		level = persistence.LevelWarning
		reasons = append(reasons, "mapping is writable and executable at the same time")
	}
	switch path {
	case "[vdso]", "[vsyscall]":
		return persistence.Finding{}, false
	case "[stack]", "[heap]":
		level = persistence.LevelWarning
		reasons = append(reasons, "process stack or heap has execute permission")
	default:
		switch {
		case path == "" || strings.HasPrefix(path, "["):
			level = maxLevel(level, persistence.LevelReview)
			reasons = append(reasons, "anonymous executable memory mapping is present")
		case isMemfd(path):
			level = persistence.LevelWarning
			reasons = append(reasons, "executable mapping is backed by a memory file")
		case isVolatilePath(path):
			level = persistence.LevelWarning
			reasons = append(reasons, "executable mapping comes from a temporary writable location")
		case filepath.IsAbs(path) && !deleted:
			cacheKey := process.RootContext + "|" + path
			cached, found := cache[cacheKey]
			if !found {
				cached = verifier.Verify(path)
				cache[cacheKey] = cached
			}
			evidence = cached
			switch evidence.Provenance {
			case persistence.ProvenancePackageModified:
				level = persistence.LevelWarning
				reasons = append(reasons, "mapped executable path differs from its local package manifest")
			case persistence.ProvenanceLocal:
				level = maxLevel(level, persistence.LevelReview)
				reasons = append(reasons, "mapped executable path is not package-owned")
			case persistence.ProvenancePackageOwned:
				level = maxLevel(level, persistence.LevelReview)
				reasons = append(reasons, "mapped executable path is package-owned but has no usable digest")
			}
		}
	}
	if deleted {
		level = maxLevel(level, persistence.LevelReview)
		reasons = append(reasons, "executable mapping has been unlinked")
	}
	if len(reasons) == 0 {
		return persistence.Finding{}, false
	}
	name := path
	if name == "" {
		name = "anonymous executable mapping"
	}
	return persistence.Finding{
		ID:             fmt.Sprintf("loader|map|%s|%s", process.ID, mapping.address),
		Level:          level,
		Mechanism:      "executable memory mapping",
		Name:           fmt.Sprintf("%s (%d): %s", process.Name, process.PID, filepath.Base(name)),
		Path:           path,
		User:           process.User,
		Command:        process.Command,
		Source:         "procfs process maps",
		Scope:          "process",
		Unit:           process.Service,
		Role:           "executable mapping",
		Enablement:     mapping.perms,
		Provenance:     evidence.Provenance,
		Package:        evidence.Package,
		PackageManager: evidence.PackageManager,
		Integrity:      evidence.Integrity,
		Reason:         strings.Join(compactStrings(reasons), "; "),
		Recommendation: "Inspect the mapped object, process ancestry, package source, and related network activity.",
	}, true
}

func parseProcStat(value string) (procIdentity, error) {
	open := strings.IndexByte(value, '(')
	close := strings.LastIndex(value, ") ")
	if open < 0 || close <= open {
		return procIdentity{}, errors.New("malformed proc stat command")
	}
	fields := strings.Fields(value[close+2:])
	if len(fields) <= 19 {
		return procIdentity{}, errors.New("truncated proc stat")
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return procIdentity{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procIdentity{}, err
	}
	return procIdentity{name: value[open+1 : close], state: fields[0], ppid: ppid, startTime: start}, nil
}

func parseProcStatus(value string) procStatus {
	status := procStatus{}
	for _, line := range strings.Split(value, "\n") {
		key, raw, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(raw)
		switch key {
		case "Uid":
			if len(fields) >= 2 {
				uid, _ := strconv.ParseUint(fields[0], 10, 32)
				euid, _ := strconv.ParseUint(fields[1], 10, 32)
				status.uid, status.euid = uint32(uid), uint32(euid)
			}
		case "CapEff":
			if len(fields) > 0 {
				status.capEff = fields[0]
			}
		case "TracerPid":
			if len(fields) > 0 {
				status.tracerPID, _ = strconv.Atoi(fields[0])
			}
		case "NoNewPrivs":
			status.noNewPrivs = len(fields) > 0 && fields[0] == "1"
		case "Seccomp":
			if len(fields) > 0 {
				status.seccomp, _ = strconv.Atoi(fields[0])
			}
		}
	}
	return status
}

func parseMapsLine(line string) (mappedObject, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return mappedObject{}, false
	}
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return mappedObject{}, false
	}
	path := ""
	if len(fields) > 5 {
		path = strings.Join(fields[5:], " ")
	}
	return mappedObject{address: fields[0], perms: fields[1], inode: inode, path: path}, true
}

type loaderVariable struct {
	name  string
	value string
}

func parseLoaderEnvironment(data []byte) []loaderVariable {
	wanted := map[string]bool{
		"LD_PRELOAD": true, "LD_AUDIT": true, "LD_LIBRARY_PATH": true,
		"GLIBC_TUNABLES": true, "LD_DEBUG": true, "LD_PROFILE": true,
	}
	result := make([]loaderVariable, 0)
	for _, item := range strings.Split(strings.TrimRight(string(data), "\x00"), "\x00") {
		name, value, found := strings.Cut(item, "=")
		if found && wanted[name] && value != "" {
			result = append(result, loaderVariable{name: name, value: value})
		}
	}
	return result
}

func parsePreload(value string) []string {
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		lines[index] = line
	}
	return strings.FieldsFunc(strings.Join(lines, "\n"), func(char rune) bool {
		return char == ':' || char == ' ' || char == '\t' || char == '\r' || char == '\n'
	})
}

func splitLoaderPaths(value string) []string {
	return strings.FieldsFunc(value, func(char rune) bool { return char == ':' || char == ' ' || char == '\t' })
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

func readUsers(path string) map[uint32]string {
	users := make(map[uint32]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return users
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.ParseUint(fields[2], 10, 32)
		if err == nil {
			users[uint32(uid)] = fields[0]
		}
	}
	return users
}

func processRootKey(procRoot string, pid int) (string, error) {
	base := filepath.Join(procRoot, strconv.Itoa(pid))
	rootInfo, err := os.Stat(filepath.Join(base, "root"))
	if err != nil {
		return "", err
	}
	native, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("process root has no Linux file identity")
	}
	mountNamespace, err := os.Readlink(filepath.Join(base, "ns/mnt"))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%x:%x", mountNamespace, uint64(native.Dev), native.Ino), nil
}

func userName(users map[uint32]string, uid uint32) string {
	if value := users[uid]; value != "" {
		return value
	}
	return strconv.FormatUint(uint64(uid), 10)
}

func serviceFromCgroup(data string) string {
	fallback := ""
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, component := range strings.Split(parts[2], "/") {
			switch {
			case strings.HasSuffix(component, ".service"):
				return component
			case fallback == "" && strings.HasSuffix(component, ".scope"):
				fallback = component
			}
		}
	}
	return fallback
}

func nonzeroHex(value string) bool { return strings.Trim(value, "0") != "" }

func isMemfd(path string) bool {
	path = strings.ToLower(path)
	return strings.Contains(path, "memfd:") || strings.Contains(path, "/memfd/")
}

func isVolatilePath(path string) bool {
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, candidate := range values {
		if candidate == value {
			return values
		}
	}
	return append(values, value)
}

func compactStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func maxLevel(left, right persistence.Level) persistence.Level {
	if levelRank(right) > levelRank(left) {
		return right
	}
	return left
}

func levelRank(level persistence.Level) int {
	switch level {
	case persistence.LevelWarning:
		return 3
	case persistence.LevelReview:
		return 2
	default:
		return 1
	}
}
