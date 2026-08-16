package dnsmon

import "errors"

var ErrUnsupported = errors.New("eBPF DNS monitoring requires Linux with cgroup v2")

type PacketMonitor interface {
	Start() error
	Packets() <-chan Packet
	Errors() <-chan error
	Close() error
}
