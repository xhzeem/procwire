//go:build !linux

package observe

func LookupProcess(pid int) Process {
	return Process{PID: pid}
}
