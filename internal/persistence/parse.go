package persistence

import (
	"bufio"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

type unitDetails struct {
	user        string
	commands    []string
	schedule    []string
	executables []string
}

func parseUnit(data string) unitDetails {
	details := unitDetails{}
	for _, line := range logicalLines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch {
		case key == "User":
			details.user = value
		case strings.HasPrefix(key, "Exec") && value != "":
			details.commands = append(details.commands, key+"="+value)
			if executable := commandExecutable(value); executable != "" {
				details.executables = append(details.executables, executable)
			}
		case key == "OnCalendar" || key == "OnActiveSec" || key == "OnBootSec" ||
			key == "OnStartupSec" || key == "OnUnitActiveSec" || key == "OnUnitInactiveSec":
			details.schedule = append(details.schedule, key+"="+value)
		}
	}
	return details
}

func commandExecutable(command string) string {
	command = strings.TrimSpace(command)
	for command != "" {
		if strings.ContainsRune("-@:+!|", rune(command[0])) {
			command = strings.TrimSpace(command[1:])
			continue
		}
		break
	}
	fields := strings.Fields(command)
	for len(fields) > 0 {
		token := strings.Trim(fields[0], "\"'")
		if strings.Contains(token, "=") && !strings.HasPrefix(token, "/") {
			fields = fields[1:]
			continue
		}
		if filepath.IsAbs(token) {
			return filepath.Clean(token)
		}
		return ""
	}
	return ""
}

func logicalLines(data string) []string {
	result := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 4*1024*1024)
	current := ""
	for scanner.Scan() {
		line := scanner.Text()
		if current != "" {
			current += strings.TrimSpace(line)
		} else {
			current = line
		}
		if strings.HasSuffix(strings.TrimSpace(current), "\\") {
			current = strings.TrimSuffix(strings.TrimSpace(current), "\\") + " "
			continue
		}
		result = append(result, current)
		current = ""
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

type cronEntry struct {
	line     int
	user     string
	schedule string
	command  string
}

func parseCron(data string, systemFile bool) []cronEntry {
	entries := make([]cronEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 4*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || isEnvironmentAssignment(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entry := cronEntry{line: lineNumber}
		commandAt := 0
		if strings.HasPrefix(fields[0], "@") {
			entry.schedule = fields[0]
			commandAt = 1
		} else {
			if len(fields) < 6 {
				continue
			}
			entry.schedule = strings.Join(fields[:5], " ")
			commandAt = 5
		}
		if systemFile {
			if commandAt >= len(fields) {
				continue
			}
			entry.user = fields[commandAt]
			commandAt++
		}
		if commandAt >= len(fields) {
			continue
		}
		entry.command = strings.Join(fields[commandAt:], " ")
		entries = append(entries, entry)
	}
	return entries
}

func parseAnacron(data string) []cronEntry {
	entries := make([]cronEntry, 0)
	scanner := bufio.NewScanner(strings.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 4*1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || isEnvironmentAssignment(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		entries = append(entries, cronEntry{
			line:     lineNumber,
			user:     "root",
			schedule: fmt.Sprintf("period=%s delay=%s", fields[0], fields[1]),
			command:  strings.Join(fields[3:], " "),
		})
	}
	return entries
}

func isEnvironmentAssignment(line string) bool {
	key, _, found := strings.Cut(line, "=")
	if !found {
		return false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	for index, char := range key {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' ||
			(index > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

func classifyCommand(command string) (Level, string) {
	lower := strings.ToLower(command)
	reasons := make([]string, 0)
	for _, path := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.Contains(lower, path) {
			reasons = append(reasons, "references an executable or file in a temporary writable location")
			break
		}
	}
	if (strings.Contains(lower, "curl ") || strings.Contains(lower, "wget ")) &&
		strings.Contains(lower, "|") &&
		(strings.Contains(lower, " sh") || strings.Contains(lower, "bash")) {
		reasons = append(reasons, "downloads content and pipes it to a shell")
	}
	for _, indicator := range []string{"/dev/tcp/", "nc -e ", "ncat -e ", "socat exec:"} {
		if strings.Contains(lower, indicator) {
			reasons = append(reasons, "contains a command pattern commonly used for an interactive network shell")
			break
		}
	}
	if strings.Contains(lower, "base64") && strings.Contains(lower, "-d") && strings.Contains(lower, "|") {
		reasons = append(reasons, "decodes data before passing it to another command")
	}
	reasons = slices.Compact(reasons)
	if len(reasons) > 0 {
		return LevelWarning, strings.Join(reasons, "; ")
	}
	return LevelReview, ""
}

func mechanismFromPath(path string) string {
	extension := filepath.Ext(path)
	switch extension {
	case ".service":
		return "systemd service"
	case ".timer":
		return "systemd timer"
	case ".socket":
		return "systemd socket"
	case ".path":
		return "systemd path"
	case ".mount":
		return "systemd mount"
	case ".automount":
		return "systemd automount"
	case ".swap":
		return "systemd swap"
	case ".conf":
		return "systemd override"
	default:
		return fmt.Sprintf("systemd %s", strings.TrimPrefix(extension, "."))
	}
}
