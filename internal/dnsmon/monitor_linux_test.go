//go:build linux

package dnsmon

import (
	"errors"
	"testing"

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

func hasBuiltinCall(instructions asm.Instructions, function asm.BuiltinFunc) bool {
	for index := range instructions {
		instruction := &instructions[index]
		if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == function {
			return true
		}
	}
	return false
}
