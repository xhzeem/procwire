//go:build linux

package observe

func LookupProcess(pid int) Process {
	collector := &procCollector{root: "/proc", users: readUsers("/etc/passwd")}
	return collector.readProcess(pid)
}
