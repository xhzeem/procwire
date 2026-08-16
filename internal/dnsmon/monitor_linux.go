//go:build linux

package dnsmon

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/xhzeem/procwire/internal/observe"
)

const (
	dnsEventSize    = 614
	dnsPayloadSize  = 512
	dnsPayloadStart = 102
	packetQueueSize = 8192
)

type ebpfMonitor struct {
	packets chan Packet
	errors  chan error

	events  *ebpf.Map
	egress  *ebpf.Program
	ingress *ebpf.Program
	links   []link.Link
	reader  *ringbuf.Reader

	closeOnce sync.Once
	wait      sync.WaitGroup
	processes map[int]cachedProcess
}

type cachedProcess struct {
	process   observe.Process
	expiresAt time.Time
}

func NewMonitor() PacketMonitor {
	return &ebpfMonitor{
		packets:   make(chan Packet, packetQueueSize),
		errors:    make(chan error, 64),
		processes: make(map[int]cachedProcess),
	}
}

func (monitor *ebpfMonitor) Start() error {
	_ = rlimit.RemoveMemlock()
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pw_dns_events",
		Type:       ebpf.RingBuf,
		MaxEntries: 1 << 24,
	})
	if err != nil {
		return fmt.Errorf("create DNS eBPF ring buffer: %w", err)
	}
	monitor.events = events

	egress, err := ebpf.NewProgram(dnsProgramSpec(events, 0, ebpf.AttachCGroupInetEgress))
	if err != nil {
		monitor.Close()
		return fmt.Errorf("load DNS egress eBPF program: %w", err)
	}
	monitor.egress = egress
	ingress, err := ebpf.NewProgram(dnsProgramSpec(events, 1, ebpf.AttachCGroupInetIngress))
	if err != nil {
		monitor.Close()
		return fmt.Errorf("load DNS ingress eBPF program: %w", err)
	}
	monitor.ingress = ingress

	cgroupPath, err := detectCgroupPath()
	if err != nil {
		monitor.Close()
		return err
	}
	for _, options := range []link.CgroupOptions{
		{Path: cgroupPath, Attach: ebpf.AttachCGroupInetEgress, Program: egress},
		{Path: cgroupPath, Attach: ebpf.AttachCGroupInetIngress, Program: ingress},
	} {
		attached, err := link.AttachCgroup(options)
		if err != nil {
			monitor.Close()
			return fmt.Errorf("attach DNS eBPF program to %s: %w", cgroupPath, err)
		}
		monitor.links = append(monitor.links, attached)
	}

	reader, err := ringbuf.NewReader(events)
	if err != nil {
		monitor.Close()
		return fmt.Errorf("open DNS eBPF ring reader: %w", err)
	}
	monitor.reader = reader
	monitor.wait.Add(1)
	go monitor.readLoop()
	return nil
}

func (monitor *ebpfMonitor) Packets() <-chan Packet { return monitor.packets }
func (monitor *ebpfMonitor) Errors() <-chan error   { return monitor.errors }

func (monitor *ebpfMonitor) Close() error {
	var closeErr error
	monitor.closeOnce.Do(func() {
		if monitor.reader != nil {
			closeErr = errors.Join(closeErr, monitor.reader.Close())
		}
		for _, attached := range monitor.links {
			closeErr = errors.Join(closeErr, attached.Close())
		}
		if monitor.egress != nil {
			closeErr = errors.Join(closeErr, monitor.egress.Close())
		}
		if monitor.ingress != nil {
			closeErr = errors.Join(closeErr, monitor.ingress.Close())
		}
		if monitor.events != nil {
			closeErr = errors.Join(closeErr, monitor.events.Close())
		}
		monitor.wait.Wait()
		close(monitor.packets)
		close(monitor.errors)
	})
	return closeErr
}

func (monitor *ebpfMonitor) readLoop() {
	defer monitor.wait.Done()
	dropped := uint64(0)
	for {
		record, err := monitor.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			monitor.sendError(fmt.Errorf("read DNS eBPF event: %w", err))
			continue
		}
		packet, err := decodeDNSPacket(record.RawSample)
		if err != nil {
			monitor.sendError(err)
			continue
		}
		if packet.Process.PID > 0 {
			packet.Process = monitor.processDetails(packet.Process.PID)
		}
		select {
		case monitor.packets <- packet:
			if dropped > 0 {
				monitor.sendError(fmt.Errorf("DNS event buffer recovered after dropping %d packets", dropped))
				dropped = 0
			}
		default:
			dropped++
		}
	}
}

func (monitor *ebpfMonitor) processDetails(pid int) observe.Process {
	now := time.Now()
	if cached, found := monitor.processes[pid]; found && cached.expiresAt.After(now) {
		return cached.process
	}
	process := observe.LookupProcess(pid)
	monitor.processes[pid] = cachedProcess{process: process, expiresAt: now.Add(5 * time.Second)}
	if len(monitor.processes) > 4096 {
		for key, cached := range monitor.processes {
			if cached.expiresAt.Before(now) {
				delete(monitor.processes, key)
			}
		}
	}
	return process
}

func (monitor *ebpfMonitor) sendError(err error) {
	select {
	case monitor.errors <- err:
	default:
	}
}

func decodeDNSPacket(data []byte) (Packet, error) {
	if len(data) < dnsEventSize {
		return Packet{}, fmt.Errorf("short DNS eBPF event: %d bytes", len(data))
	}
	payloadLength := int(binary.LittleEndian.Uint16(data[48:50]))
	if payloadLength < 0 || payloadLength > dnsPayloadSize {
		return Packet{}, fmt.Errorf("invalid DNS payload length: %d", payloadLength)
	}
	family := data[51]
	sourceAddress, err := eventAddress(family, data[70:86])
	if err != nil {
		return Packet{}, err
	}
	destinationAddress, err := eventAddress(family, data[86:102])
	if err != nil {
		return Packet{}, err
	}
	protocol := "udp"
	if data[52] == 6 {
		protocol = "tcp"
	}
	comm := strings.TrimRight(string(data[54:70]), "\x00")
	return Packet{
		CapturedAt: time.Now(),
		Protocol:   protocol,
		Source: observe.Endpoint{
			Address: sourceAddress,
			Port:    binary.LittleEndian.Uint16(data[44:46]),
		},
		Destination: observe.Endpoint{
			Address: destinationAddress,
			Port:    binary.LittleEndian.Uint16(data[46:48]),
		},
		Process: observe.Process{
			PID:  int(binary.LittleEndian.Uint32(data[24:28])),
			Name: comm,
		},
		UID:      binary.LittleEndian.Uint32(data[32:36]),
		GID:      binary.LittleEndian.Uint32(data[36:40]),
		CgroupID: binary.LittleEndian.Uint64(data[8:16]),
		Payload:  append([]byte(nil), data[dnsPayloadStart:dnsPayloadStart+payloadLength]...),
	}, nil
}

func eventAddress(family byte, value []byte) (netip.Addr, error) {
	switch family {
	case 4:
		var address [4]byte
		copy(address[:], value[:4])
		return netip.AddrFrom4(address), nil
	case 6:
		var address [16]byte
		copy(address[:], value[:16])
		return netip.AddrFrom16(address).Unmap(), nil
	default:
		return netip.Addr{}, fmt.Errorf("invalid DNS address family: %d", family)
	}
}

func detectCgroupPath() (string, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("open proc mounts: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return strings.ReplaceAll(fields[1], "\\040", " "), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan proc mounts: %w", err)
	}
	return "", ErrUnsupported
}

func dnsProgramSpec(events *ebpf.Map, direction byte, attach ebpf.AttachType) *ebpf.ProgramSpec {
	name := "pw_dns_egress"
	if direction == 1 {
		name = "pw_dns_ingress"
	}
	return &ebpf.ProgramSpec{
		Name:         name,
		Type:         ebpf.CGroupSKB,
		AttachType:   attach,
		License:      "GPL",
		Instructions: dnsInstructions(events, direction),
	}
}

func dnsInstructions(events *ebpf.Map, direction byte) asm.Instructions {
	instructions := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	instructions = append(instructions, loadPacketImmediate(0, asm.Byte, "", "allow")...)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.RSh.Imm(asm.R7, 4),
		asm.StoreMem(asm.RFP, -1, asm.R7, asm.Byte),
		asm.JEq.Imm(asm.R7, 4, "ipv4"),
		asm.JEq.Imm(asm.R7, 6, "ipv6"),
		asm.Ja.Label("allow"),
	)
	instructions = append(instructions, loadPacketImmediate(0, asm.Byte, "ipv4", "allow")...)
	instructions = append(instructions,
		asm.And.Imm(asm.R0, 0x0f),
		asm.LSh.Imm(asm.R0, 2),
		asm.Mov.Reg(asm.R8, asm.R0),
	)
	instructions = append(instructions, loadPacketImmediate(9, asm.Byte, "", "allow")...)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R9, asm.R0),
		asm.Ja.Label("transport"),

		asm.Mov.Imm(asm.R8, 40).WithSymbol("ipv6"),
	)
	instructions = append(instructions, loadPacketImmediate(6, asm.Byte, "", "allow")...)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R9, asm.R0),

		asm.JEq.Imm(asm.R9, 17, "udp").WithSymbol("transport"),
		asm.JEq.Imm(asm.R9, 6, "tcp"),
		asm.Ja.Label("allow"),
	)
	instructions = append(instructions, loadPacketDynamic(asm.R8, 0, asm.Half, "udp", "allow")...)
	instructions = append(instructions,
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
	)
	instructions = append(instructions, loadPacketDynamic(asm.R8, 2, asm.Half, "", "allow")...)
	instructions = append(instructions,
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.StoreMem(asm.RFP, -6, asm.R0, asm.Half),
		asm.Add.Imm(asm.R8, 8),
		asm.Mov.Imm(asm.R9, 17),
		asm.Ja.Label("check_port"),
	)
	instructions = append(instructions, loadPacketDynamic(asm.R8, 0, asm.Half, "tcp", "allow")...)
	instructions = append(instructions,
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.StoreMem(asm.RFP, -4, asm.R0, asm.Half),
	)
	instructions = append(instructions, loadPacketDynamic(asm.R8, 2, asm.Half, "", "allow")...)
	instructions = append(instructions,
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.StoreMem(asm.RFP, -6, asm.R0, asm.Half),
	)
	instructions = append(instructions, loadPacketDynamic(asm.R8, 12, asm.Byte, "", "allow")...)
	instructions = append(instructions,
		asm.RSh.Imm(asm.R0, 4),
		asm.LSh.Imm(asm.R0, 2),
		asm.Add.Reg(asm.R8, asm.R0),
		asm.Mov.Imm(asm.R9, 6),
	)
	if direction == 0 {
		instructions = append(instructions,
			asm.LoadMem(asm.R0, asm.RFP, -6, asm.Half).WithSymbol("check_port"),
			asm.JNE.Imm(asm.R0, 53, "allow"),
		)
	} else {
		instructions = append(instructions,
			asm.LoadMem(asm.R0, asm.RFP, -4, asm.Half).WithSymbol("check_port"),
			asm.JNE.Imm(asm.R0, 53, "allow"),
		)
	}
	instructions = append(instructions,
		asm.StoreMem(asm.RFP, -2, asm.R9, asm.Byte),
		asm.StoreMem(asm.RFP, -12, asm.R8, asm.Word),
		asm.LoadMem(asm.R0, asm.R6, 0, asm.Word),
		asm.JLE.Reg(asm.R0, asm.R8, "allow"),
		asm.Sub.Reg(asm.R0, asm.R8),
		asm.JLE.Imm(asm.R0, dnsPayloadSize, "length_bounded"),
		asm.Mov.Imm(asm.R0, dnsPayloadSize),
		asm.JEq.Imm(asm.R0, 0, "allow").WithSymbol("length_bounded"),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),

		asm.LoadMapPtr(asm.R1, events.FD()),
		asm.Mov.Imm(asm.R2, dnsEventSize),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Imm(asm.R0, 0),
	)
	for offset := int16(0); offset <= 600; offset += 8 {
		instructions = append(instructions, asm.StoreMem(asm.R7, offset, asm.R0, asm.DWord))
	}
	instructions = append(instructions,
		asm.StoreMem(asm.R7, 608, asm.R0, asm.Word),
		asm.StoreMem(asm.R7, 612, asm.R0, asm.Half),

		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.R7, 0, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.FnGetSocketCookie.Call(),
		asm.StoreMem(asm.R7, 16, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.R6, 40, asm.Word),
		asm.StoreMem(asm.R7, 40, asm.R0, asm.Word),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Half),
		asm.StoreMem(asm.R7, 44, asm.R0, asm.Half),
		asm.LoadMem(asm.R0, asm.RFP, -6, asm.Half),
		asm.StoreMem(asm.R7, 46, asm.R0, asm.Half),
		asm.LoadMem(asm.R0, asm.RFP, -16, asm.Word),
		asm.StoreMem(asm.R7, 48, asm.R0, asm.Half),
		asm.StoreImm(asm.R7, 50, int64(direction), asm.Byte),
		asm.LoadMem(asm.R0, asm.RFP, -1, asm.Byte),
		asm.StoreMem(asm.R7, 51, asm.R0, asm.Byte),
		asm.LoadMem(asm.R0, asm.RFP, -2, asm.Byte),
		asm.StoreMem(asm.R7, 52, asm.R0, asm.Byte),
	)
	if direction == 0 {
		instructions = append(instructions,
			asm.FnGetCurrentCgroupId.Call(),
			asm.StoreMem(asm.R7, 8, asm.R0, asm.DWord),
			asm.FnGetCurrentPidTgid.Call(),
			asm.StoreMem(asm.R7, 28, asm.R0, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R0),
			asm.RSh.Imm(asm.R1, 32),
			asm.StoreMem(asm.R7, 24, asm.R1, asm.Word),
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.FnGetSocketUid.Call(),
			asm.StoreMem(asm.R7, 32, asm.R0, asm.Word),
		)
	}
	instructions = append(instructions,
		asm.LoadMem(asm.R0, asm.RFP, -1, asm.Byte),
		asm.JEq.Imm(asm.R0, 4, "address_ipv4"),
		asm.Ja.Label("address_ipv6"),
	)
	instructions = appendAddressCopies(instructions, "address_ipv4", 12, 16, 4)
	instructions = append(instructions, asm.Ja.Label("payload"))
	instructions = appendAddressCopies(instructions, "address_ipv6", 8, 24, 16)
	instructions = append(instructions,
		asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("payload"),
		asm.LoadMem(asm.R2, asm.RFP, -12, asm.Word),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, dnsPayloadStart),
		asm.LoadMem(asm.R4, asm.RFP, -16, asm.Word),
		asm.FnSkbLoadBytes.Call(),
		asm.JSLT.Imm(asm.R0, 0, "discard"),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
		asm.Ja.Label("allow"),
		asm.Mov.Reg(asm.R1, asm.R7).WithSymbol("discard"),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufDiscard.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return instructions
}

func appendAddressCopies(instructions asm.Instructions, symbol string, sourceOffset, destinationOffset, length int) asm.Instructions {
	for index := 0; index < length; index++ {
		loadSymbol := ""
		if index == 0 {
			loadSymbol = symbol
		}
		instructions = append(instructions, loadPacketImmediate(int32(sourceOffset+index), asm.Byte, loadSymbol, "discard")...)
		instructions = append(instructions, asm.StoreMem(asm.R7, int16(70+index), asm.R0, asm.Byte))
	}
	for index := 0; index < length; index++ {
		instructions = append(instructions, loadPacketImmediate(int32(destinationOffset+index), asm.Byte, "", "discard")...)
		instructions = append(instructions, asm.StoreMem(asm.R7, int16(86+index), asm.R0, asm.Byte))
	}
	return instructions
}

func loadPacketImmediate(offset int32, size asm.Size, symbol, errorLabel string) asm.Instructions {
	first := asm.Mov.Reg(asm.R1, asm.R6)
	if symbol != "" {
		first = first.WithSymbol(symbol)
	}
	return asm.Instructions{
		first,
		asm.Mov.Imm(asm.R2, offset),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -32),
		asm.Mov.Imm(asm.R4, int32(size.Sizeof())),
		asm.FnSkbLoadBytes.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R0, asm.RFP, -32, size),
	}
}

func loadPacketDynamic(offset asm.Register, addition int32, size asm.Size, symbol, errorLabel string) asm.Instructions {
	first := asm.Mov.Reg(asm.R1, asm.R6)
	if symbol != "" {
		first = first.WithSymbol(symbol)
	}
	instructions := asm.Instructions{
		first,
		asm.Mov.Reg(asm.R2, offset),
	}
	if addition != 0 {
		instructions = append(instructions, asm.Add.Imm(asm.R2, addition))
	}
	return append(instructions,
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -32),
		asm.Mov.Imm(asm.R4, int32(size.Sizeof())),
		asm.FnSkbLoadBytes.Call(),
		asm.JSLT.Imm(asm.R0, 0, errorLabel),
		asm.LoadMem(asm.R0, asm.RFP, -32, size),
	)
}
