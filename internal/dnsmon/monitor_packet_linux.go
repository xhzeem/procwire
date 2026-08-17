//go:build linux

package dnsmon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/xhzeem/procwire/internal/observe"
)

const afPacketBufferSize = 65_535

type afPacketMonitor struct {
	packets chan Packet
	errors  chan error
	fd      int
	closed  chan struct{}

	closeOnce sync.Once
	wait      sync.WaitGroup
}

func newAFPacketMonitor() *afPacketMonitor {
	return &afPacketMonitor{
		packets: make(chan Packet, packetQueueSize),
		errors:  make(chan error, 64),
		fd:      -1,
		closed:  make(chan struct{}),
	}
}

func (monitor *afPacketMonitor) Start() error {
	protocol := networkShort(unix.ETH_P_ALL)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(protocol))
	if err != nil {
		return fmt.Errorf("open AF_PACKET DNS capture socket: %w", err)
	}
	monitor.fd = fd
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol}); err != nil {
		_ = unix.Close(fd)
		monitor.fd = -1
		return fmt.Errorf("bind AF_PACKET DNS capture socket: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	timeout := unix.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		monitor.fd = -1
		return fmt.Errorf("set AF_PACKET DNS capture timeout: %w", err)
	}
	monitor.wait.Add(1)
	go monitor.readLoop(fd)
	return nil
}

func (monitor *afPacketMonitor) Packets() <-chan Packet { return monitor.packets }
func (monitor *afPacketMonitor) Errors() <-chan error   { return monitor.errors }

func (monitor *afPacketMonitor) Close() error {
	var closeErr error
	monitor.closeOnce.Do(func() {
		close(monitor.closed)
		if monitor.fd >= 0 {
			closeErr = unix.Close(monitor.fd)
			monitor.fd = -1
		}
		monitor.wait.Wait()
		close(monitor.packets)
		close(monitor.errors)
	})
	return closeErr
}

func (monitor *afPacketMonitor) readLoop(fd int) {
	defer monitor.wait.Done()
	buffer := make([]byte, afPacketBufferSize)
	dropped := uint64(0)
	for {
		length, _, err := unix.Recvfrom(fd, buffer, 0)
		if err != nil {
			select {
			case <-monitor.closed:
				return
			default:
			}
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			monitor.sendError(fmt.Errorf("read AF_PACKET DNS frame: %w", err))
			continue
		}
		packet, found := decodeAFPacket(buffer[:length])
		if !found {
			continue
		}
		select {
		case monitor.packets <- packet:
			if dropped > 0 {
				monitor.sendError(fmt.Errorf("AF_PACKET DNS queue recovered after dropping %d packets", dropped))
				dropped = 0
			}
		default:
			dropped++
		}
	}
}

func (monitor *afPacketMonitor) sendError(err error) {
	select {
	case monitor.errors <- err:
	default:
	}
}

func decodeAFPacket(data []byte) (Packet, bool) {
	if len(data) < 1 {
		return Packet{}, false
	}
	var source, destination netip.Addr
	var protocol byte
	var transport []byte
	switch data[0] >> 4 {
	case 4:
		if len(data) < 20 {
			return Packet{}, false
		}
		headerLength := int(data[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(data[2:4]))
		if headerLength < 20 || totalLength < headerLength || totalLength > len(data) || binary.BigEndian.Uint16(data[6:8])&0x3fff != 0 {
			return Packet{}, false
		}
		source = netip.AddrFrom4([4]byte(data[12:16]))
		destination = netip.AddrFrom4([4]byte(data[16:20]))
		protocol = data[9]
		transport = data[headerLength:totalLength]
	case 6:
		if len(data) < 40 {
			return Packet{}, false
		}
		totalLength := 40 + int(binary.BigEndian.Uint16(data[4:6]))
		if totalLength < 40 || totalLength > len(data) {
			return Packet{}, false
		}
		var sourceBytes, destinationBytes [16]byte
		copy(sourceBytes[:], data[8:24])
		copy(destinationBytes[:], data[24:40])
		source = netip.AddrFrom16(sourceBytes).Unmap()
		destination = netip.AddrFrom16(destinationBytes).Unmap()
		protocol = data[6]
		transport = data[40:totalLength]
	default:
		return Packet{}, false
	}

	var sourcePort, destinationPort uint16
	var payload []byte
	protocolName := ""
	switch protocol {
	case unix.IPPROTO_UDP:
		if len(transport) < 8 {
			return Packet{}, false
		}
		length := int(binary.BigEndian.Uint16(transport[4:6]))
		if length < 8 || length > len(transport) {
			return Packet{}, false
		}
		sourcePort = binary.BigEndian.Uint16(transport[0:2])
		destinationPort = binary.BigEndian.Uint16(transport[2:4])
		payload = transport[8:length]
		protocolName = "udp"
	case unix.IPPROTO_TCP:
		if len(transport) < 20 {
			return Packet{}, false
		}
		headerLength := int(transport[12]>>4) * 4
		if headerLength < 20 || headerLength > len(transport) {
			return Packet{}, false
		}
		sourcePort = binary.BigEndian.Uint16(transport[0:2])
		destinationPort = binary.BigEndian.Uint16(transport[2:4])
		payload = transport[headerLength:]
		protocolName = "tcp"
	default:
		return Packet{}, false
	}
	if sourcePort != 53 && destinationPort != 53 {
		return Packet{}, false
	}
	minimumPayload := 12
	if protocolName == "tcp" {
		minimumPayload += 2
	}
	if len(payload) < minimumPayload {
		return Packet{}, false
	}
	return Packet{
		CapturedAt:  time.Now(),
		Protocol:    protocolName,
		Source:      observe.Endpoint{Address: source, Port: sourcePort},
		Destination: observe.Endpoint{Address: destination, Port: destinationPort},
		Payload:     append([]byte(nil), payload...),
	}, true
}

func networkShort(value uint16) uint16 {
	return value<<8 | value>>8
}
