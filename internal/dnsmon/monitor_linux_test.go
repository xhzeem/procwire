//go:build linux

package dnsmon

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/asm"
)

func TestUnsupportedCurrentPIDHelper(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "named helper", err: errors.New("invalid argument: unknown func bpf_get_current_pid_tgid#14"), want: true},
		{name: "numbered helper", err: errors.New("program of this type cannot use helper func #14"), want: true},
		{name: "other helper", err: errors.New("unknown func bpf_get_socket_uid#47")},
		{name: "permission", err: errors.New("operation not permitted")},
		{name: "nil"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := unsupportedCurrentPIDHelper(test.err); got != test.want {
				t.Fatalf("unsupportedCurrentPIDHelper() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDNSInstructionsCanOmitPIDHelper(t *testing.T) {
	if !hasBuiltinCall(dnsInstructions(-1, 0, true), asm.FnGetCurrentPidTgid) {
		t.Fatal("full egress program does not contain PID helper")
	}
	if hasBuiltinCall(dnsInstructions(-1, 0, false), asm.FnGetCurrentPidTgid) {
		t.Fatal("compatible egress program still contains PID helper")
	}
	if hasBuiltinCall(dnsInstructions(-1, 1, true), asm.FnGetCurrentPidTgid) {
		t.Fatal("ingress program contains PID helper")
	}
}

func TestDecodeAFPacketIPv4UDP(t *testing.T) {
	payload := dnsQuery("example.com")
	data := make([]byte, 20+8+len(payload))
	data[0] = 0x45
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	data[8] = 64
	data[9] = 17
	copy(data[12:16], netip.MustParseAddr("192.0.2.10").AsSlice())
	copy(data[16:20], netip.MustParseAddr("1.1.1.1").AsSlice())
	binary.BigEndian.PutUint16(data[20:22], 53000)
	binary.BigEndian.PutUint16(data[22:24], 53)
	binary.BigEndian.PutUint16(data[24:26], uint16(8+len(payload)))
	copy(data[28:], payload)

	packet, found := decodeAFPacket(data)
	if !found {
		t.Fatal("IPv4 UDP DNS packet was not decoded")
	}
	if packet.Protocol != "udp" || packet.Source.Port != 53000 || packet.Destination.Port != 53 {
		t.Fatalf("decoded packet = %#v", packet)
	}
	events, err := Parse(packet)
	if err != nil || len(events) != 1 || len(events[0].Questions) != 1 || events[0].Questions[0].Name != "example.com" {
		t.Fatalf("parsed fallback event = %#v, err = %v", events, err)
	}

	binary.BigEndian.PutUint16(data[22:24], 443)
	if _, found := decodeAFPacket(data); found {
		t.Fatal("non-DNS packet was accepted")
	}
}

func TestAFPacketMonitorCapturesLoopbackDNS(t *testing.T) {
	if os.Getenv("PROCWIRE_AF_PACKET_TEST") != "1" {
		t.Skip("set PROCWIRE_AF_PACKET_TEST=1 in a privileged Linux environment")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatalf("listen on loopback DNS port: %v", err)
	}
	defer server.Close()

	monitor := newAFPacketMonitor()
	if err := monitor.Start(); err != nil {
		t.Fatalf("start AF_PACKET monitor: %v", err)
	}
	defer monitor.Close()
	time.Sleep(50 * time.Millisecond)

	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial loopback DNS server: %v", err)
	}
	if _, err := client.Write(dnsQuery("example.com")); err != nil {
		client.Close()
		t.Fatalf("write loopback DNS query: %v", err)
	}
	client.Close()

	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case packet := <-monitor.Packets():
			events, err := Parse(packet)
			if err == nil && len(events) == 1 && len(events[0].Questions) == 1 && events[0].Questions[0].Name == "example.com" {
				return
			}
		case err := <-monitor.Errors():
			t.Fatalf("AF_PACKET monitor error: %v", err)
		case <-timer.C:
			t.Fatal("AF_PACKET monitor did not capture loopback DNS query")
		}
	}
}

func hasBuiltinCall(instructions asm.Instructions, function asm.BuiltinFunc) bool {
	for index := range instructions {
		instruction := &instructions[index]
		if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == function {
			return true
		}
	}
	return false
}
