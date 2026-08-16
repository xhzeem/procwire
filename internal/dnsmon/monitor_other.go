//go:build !linux

package dnsmon

type unsupportedMonitor struct {
	packets chan Packet
	errors  chan error
}

func NewMonitor() PacketMonitor {
	return &unsupportedMonitor{
		packets: make(chan Packet),
		errors:  make(chan error),
	}
}

func (monitor *unsupportedMonitor) Start() error           { return ErrUnsupported }
func (monitor *unsupportedMonitor) Packets() <-chan Packet { return monitor.packets }
func (monitor *unsupportedMonitor) Errors() <-chan error   { return monitor.errors }
func (monitor *unsupportedMonitor) Close() error           { return nil }
