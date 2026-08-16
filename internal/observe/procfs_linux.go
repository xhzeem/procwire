//go:build linux

package observe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type procCollector struct {
	root  string
	users map[int]string
}

func NewCollector() Collector {
	return &procCollector{root: "/proc", users: readUsers("/etc/passwd")}
}

func (c *procCollector) Snapshot(ctx context.Context) (Snapshot, error) {
	tables := []struct {
		name string
		path string
	}{
		{name: "tcp4", path: "net/tcp"},
		{name: "tcp6", path: "net/tcp6"},
		{name: "udp4", path: "net/udp"},
		{name: "udp6", path: "net/udp6"},
	}

	raw := make([]rawSocket, 0)
	warnings := make([]string, 0)
	tableErrors := make([]string, 0)
	readTables := 0
	for _, table := range tables {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		data, err := os.ReadFile(filepath.Join(c.root, table.path))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				tableErrors = append(tableErrors, fmt.Sprintf("cannot read /proc/%s: %v", table.path, err))
			}
			continue
		}
		items, err := parseSocketTable(table.name, data)
		if err != nil {
			tableErrors = append(tableErrors, err.Error())
			continue
		}
		readTables++
		raw = append(raw, items...)
	}
	if readTables == 0 {
		return Snapshot{}, errors.New("no procfs network socket tables could be read")
	}
	if len(tableErrors) > 0 {
		warnings = append(warnings, tableErrors...)
		return Snapshot{CapturedAt: time.Now(), Warnings: warnings}, fmt.Errorf("incomplete procfs snapshot: %s", strings.Join(tableErrors, "; "))
	}

	targets := make(map[string]struct{})
	for _, socket := range raw {
		if socket.inode != "0" {
			targets[socket.inode] = struct{}{}
		}
	}
	owners, denied, err := c.socketOwners(ctx, targets)
	if err != nil {
		warnings = append(warnings, err.Error())
	}
	if denied > 0 {
		warnings = append(warnings, fmt.Sprintf("process attribution is partial: %d fd directories were not readable", denied))
	}

	connections := make([]Connection, 0, len(raw))
	for _, socket := range raw {
		connection := socket.connection
		connection.Owners = owners[socket.inode]
		connections = append(connections, connection)
	}
	inferDirections(connections)

	return Snapshot{
		CapturedAt:  time.Now(),
		Connections: connections,
		Warnings:    warnings,
	}, nil
}

func (c *procCollector) socketOwners(ctx context.Context, targets map[string]struct{}) (map[string][]Process, int, error) {
	owners := make(map[string][]Process)
	if len(targets) == 0 {
		return owners, 0, nil
	}
	entries, err := os.ReadDir(c.root)
	if err != nil {
		return owners, 0, fmt.Errorf("list procfs: %w", err)
	}
	denied := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return owners, denied, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		fdPath := filepath.Join(c.root, entry.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				denied++
			}
			continue
		}
		matched := make(map[string][]string)
		for _, fd := range fds {
			fullPath := filepath.Join(fdPath, fd.Name())
			target, err := os.Readlink(fullPath)
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			if _, wanted := targets[inode]; wanted {
				matched[inode] = append(matched[inode], fullPath)
			}
		}
		if len(matched) == 0 {
			continue
		}
		startBefore := processStartTime(rootedPID(c.root, pid))
		process := c.readProcess(pid)
		startAfter := processStartTime(rootedPID(c.root, pid))
		if startBefore == 0 || startBefore != startAfter {
			continue
		}
		process.StartTime = startBefore
		for inode, paths := range matched {
			for _, path := range paths {
				target, err := os.Readlink(path)
				currentInode, ok := socketInode(target)
				if err == nil && ok && currentInode == inode {
					owners[inode] = append(owners[inode], process)
					break
				}
			}
		}
	}
	for inode := range owners {
		sort.Slice(owners[inode], func(i, j int) bool {
			return owners[inode][i].PID < owners[inode][j].PID
		})
	}
	return owners, denied, nil
}

func (c *procCollector) readProcess(pid int) Process {
	root := rootedPID(c.root, pid)
	process := Process{PID: pid}
	if data, err := os.ReadFile(filepath.Join(root, "comm")); err == nil {
		process.Name = strings.TrimSpace(string(data))
	}
	if target, err := os.Readlink(filepath.Join(root, "exe")); err == nil {
		process.Executable = target
	}
	if data, err := os.ReadFile(filepath.Join(root, "cmdline")); err == nil {
		process.Command = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}
	if data, err := os.ReadFile(filepath.Join(root, "status")); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) > 1 {
				uid, _ := strconv.Atoi(fields[1])
				process.User = c.userName(uid)
			}
			break
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "cgroup")); err == nil {
		process.Service = serviceFromCgroup(string(data))
	}
	return process
}

func rootedPID(root string, pid int) string {
	return filepath.Join(root, strconv.Itoa(pid))
}

func processStartTime(root string) uint64 {
	data, err := os.ReadFile(filepath.Join(root, "stat"))
	if err != nil {
		return 0
	}
	closing := strings.LastIndex(string(data), ")")
	if closing < 0 || closing+2 >= len(data) {
		return 0
	}
	fields := strings.Fields(string(data[closing+2:]))
	if len(fields) <= 19 {
		return 0
	}
	start, _ := strconv.ParseUint(fields[19], 10, 64)
	return start
}

func (c *procCollector) userName(uid int) string {
	if name := c.users[uid]; name != "" {
		return name
	}
	return strconv.Itoa(uid)
}

func socketInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), true
}

func serviceFromCgroup(data string) string {
	fallback := ""
	for _, line := range strings.Split(data, "\n") {
		_, path, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		_, path, found = strings.Cut(path, ":")
		if !found {
			continue
		}
		for _, component := range strings.Split(path, "/") {
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

func readUsers(path string) map[int]string {
	users := make(map[int]string)
	file, err := os.Open(path)
	if err != nil {
		return users
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err == nil {
			users[uid] = fields[0]
		}
	}
	return users
}
