package flow

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

func TestStoreDeduplicatesAndTracksLifecycle(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	base := observe.Connection{
		Network:      "tcp4",
		Local:        observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 50000},
		Remote:       observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
		State:        "ESTABLISHED",
		Direction:    observe.DirectionOutbound,
		Owners:       []observe.Process{{PID: 20, Name: "client"}},
		SocketInodes: []string{"200"},
	}
	duplicate := base
	duplicate.Owners = []observe.Process{{PID: 10, Name: "supervisor"}}
	duplicate.SocketInodes = []string{"100"}

	events := store.Reconcile(observe.Snapshot{CapturedAt: now, Connections: []observe.Connection{base, duplicate}})
	if len(events) != 1 || events[0].Type != EventOpened {
		t.Fatalf("first reconcile events = %#v", events)
	}
	active := store.Active()
	if len(active) != 1 || len(active[0].Connection.Owners) != 2 || len(active[0].Connection.SocketInodes) != 2 {
		t.Fatalf("deduplicated flow = %#v", active)
	}
	if active[0].Connection.Owners[0].PID != 10 {
		t.Fatalf("owners were not normalized: %#v", active[0].Connection.Owners)
	}

	events = store.Reconcile(observe.Snapshot{CapturedAt: now.Add(time.Second), Connections: []observe.Connection{duplicate, base}})
	if len(events) != 0 {
		t.Fatalf("unchanged flow emitted events: %#v", events)
	}
	if observations := store.Active()[0].Observations; observations != 2 {
		t.Fatalf("observations = %d, want 2", observations)
	}

	changed := base
	changed.State = "CLOSE_WAIT"
	events = store.Reconcile(observe.Snapshot{CapturedAt: now.Add(2 * time.Second), Connections: []observe.Connection{changed}})
	if len(events) != 1 || events[0].Type != EventChanged {
		t.Fatalf("changed flow events = %#v", events)
	}

	events = store.Reconcile(observe.Snapshot{CapturedAt: now.Add(3 * time.Second)})
	if len(events) != 1 || events[0].Type != EventClosed || len(store.Active()) != 0 {
		t.Fatalf("closed flow events = %#v, active = %#v", events, store.Active())
	}
	if history := store.History(); len(history) != 1 || history[0].ActiveSockets != 0 {
		t.Fatalf("closed flow was not retained in session history: %#v", history)
	}
}

func TestHistoryAggregatesRemoteHostAndSourcePorts(t *testing.T) {
	store := NewStore()
	now := time.Now()
	connection := observe.Connection{
		Network:   "tcp4",
		Local:     observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 50001},
		Remote:    observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443},
		State:     "ESTABLISHED",
		Direction: observe.DirectionOutbound,
		Owners:    []observe.Process{{PID: 10, Name: "client", Executable: "/usr/bin/client"}},
	}
	second := connection
	second.Local.Port = 50002
	store.Reconcile(observe.Snapshot{CapturedAt: now, Connections: []observe.Connection{connection, second}})

	history := store.History()
	if len(history) != 1 {
		t.Fatalf("history rows = %d, want 1: %#v", len(history), history)
	}
	if history[0].Connections != 2 || history[0].ActiveSockets != 2 || history[0].Observations != 2 {
		t.Fatalf("unexpected aggregate counters: %#v", history[0])
	}
	if !slices.Equal(history[0].SourcePorts, []uint16{50001, 50002}) {
		t.Fatalf("source ports = %#v", history[0].SourcePorts)
	}

	store.Reconcile(observe.Snapshot{CapturedAt: now.Add(time.Second)})
	history = store.History()
	if len(history) != 1 || history[0].ActiveSockets != 0 {
		t.Fatalf("session history disappeared after close: %#v", history)
	}
}

func TestStoreCountsBoundPorts(t *testing.T) {
	store := NewStore()
	store.Reconcile(observe.Snapshot{
		CapturedAt: time.Now(),
		Connections: []observe.Connection{{
			Network:   "udp4",
			Local:     observe.Endpoint{Port: 53},
			Direction: observe.DirectionBound,
		}},
	})
	if got := store.Stats().Bound; got != 1 {
		t.Fatalf("bound count = %d, want 1", got)
	}
}

func TestDirectionChangeDoesNotCreateNewFlow(t *testing.T) {
	store := NewStore()
	now := time.Now()
	connection := observe.Connection{
		Network:   "tcp4",
		Local:     observe.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 8080},
		Remote:    observe.Endpoint{Address: netip.MustParseAddr("127.0.0.1"), Port: 50000},
		State:     "ESTABLISHED",
		Direction: observe.DirectionInbound,
	}
	opened := store.Reconcile(observe.Snapshot{CapturedAt: now, Connections: []observe.Connection{connection}})
	connection.Direction = observe.DirectionOutbound
	changed := store.Reconcile(observe.Snapshot{CapturedAt: now.Add(time.Second), Connections: []observe.Connection{connection}})
	if len(opened) != 1 || opened[0].Type != EventOpened {
		t.Fatalf("open events = %#v", opened)
	}
	if len(changed) != 0 || len(store.Active()) != 1 || store.Active()[0].ID != opened[0].Flow.ID {
		t.Fatalf("direction change created a new lifecycle: %#v", changed)
	}
}
