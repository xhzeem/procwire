package observe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

var ErrUnsupported = errors.New("procwire collectors require Linux")

type Direction string

const (
	DirectionInbound  Direction = "in"
	DirectionOutbound Direction = "out"
	DirectionListen   Direction = "listen"
	DirectionBound    Direction = "bound"
	DirectionUnknown  Direction = "unknown"
)

type Endpoint struct {
	Address netip.Addr `json:"address"`
	Port    uint16     `json:"port"`
}

func (e Endpoint) String() string {
	if !e.Address.IsValid() || e.Address.IsUnspecified() {
		if e.Port == 0 {
			return "*:*"
		}
		return fmt.Sprintf("*:%d", e.Port)
	}
	if e.Address.Is6() {
		return fmt.Sprintf("[%s]:%d", e.Address, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Address, e.Port)
}

func (e Endpoint) IsWildcard() bool {
	return !e.Address.IsValid() || e.Address.IsUnspecified()
}

type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name,omitempty"`
	Executable string `json:"executable,omitempty"`
	Command    string `json:"command,omitempty"`
	User       string `json:"user,omitempty"`
	Service    string `json:"service,omitempty"`
	StartTime  uint64 `json:"start_time_ticks,omitempty"`
}

type Connection struct {
	Network      string    `json:"network"`
	Local        Endpoint  `json:"local"`
	Remote       Endpoint  `json:"remote"`
	State        string    `json:"state"`
	Direction    Direction `json:"direction"`
	UID          int       `json:"uid"`
	Owners       []Process `json:"owners,omitempty"`
	SocketInodes []string  `json:"socket_inodes,omitempty"`
}

type Snapshot struct {
	CapturedAt  time.Time    `json:"captured_at"`
	Connections []Connection `json:"connections"`
	Warnings    []string     `json:"warnings,omitempty"`
}

type Collector interface {
	Snapshot(context.Context) (Snapshot, error)
}
