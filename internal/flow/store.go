package flow

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

type EventType string

const (
	EventOpened  EventType = "flow_open"
	EventChanged EventType = "flow_change"
	EventClosed  EventType = "flow_close"
)

type Flow struct {
	ID           string             `json:"id"`
	Connection   observe.Connection `json:"connection"`
	FirstSeen    time.Time          `json:"first_seen"`
	LastSeen     time.Time          `json:"last_seen"`
	Observations uint64             `json:"observations"`
}

type Traffic struct {
	ID             string             `json:"id"`
	LastConnection observe.Connection `json:"last_connection"`
	FirstSeen      time.Time          `json:"first_seen"`
	LastSeen       time.Time          `json:"last_seen"`
	Connections    uint64             `json:"connections"`
	Observations   uint64             `json:"observations"`
	ActiveSockets  int                `json:"active_sockets"`
	SourcePorts    []uint16           `json:"source_ports,omitempty"`
}

type Event struct {
	Type EventType `json:"type"`
	At   time.Time `json:"at"`
	Flow Flow      `json:"flow"`
}

type Stats struct {
	Active   int
	Inbound  int
	Outbound int
	Listen   int
	Bound    int
	Unknown  int
}

type Store struct {
	active      map[string]Flow
	history     map[string]Traffic
	assignments map[string]string
}

func NewStore() *Store {
	return &Store{
		active:      make(map[string]Flow),
		history:     make(map[string]Traffic),
		assignments: make(map[string]string),
	}
}

func Key(c observe.Connection) string {
	return fmt.Sprintf("%s|%s|%s", c.Network, c.Local.String(), c.Remote.String())
}

func (s *Store) Reconcile(snapshot observe.Snapshot) []Event {
	at := snapshot.CapturedAt
	if at.IsZero() {
		at = time.Now()
	}

	current := aggregate(snapshot.Connections)
	keys := make([]string, 0, len(current))
	for key := range current {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	next := make(map[string]Flow, len(current))
	events := make([]Event, 0)
	for _, key := range keys {
		connection := current[key]
		previous, exists := s.active[key]
		if !exists {
			flow := Flow{
				ID:           key,
				Connection:   connection,
				FirstSeen:    at,
				LastSeen:     at,
				Observations: 1,
			}
			next[key] = flow
			events = append(events, Event{Type: EventOpened, At: at, Flow: flow})
			continue
		}

		connection = carryAttribution(previous.Connection, connection)
		flow := previous
		flow.Connection = connection
		flow.LastSeen = at
		flow.Observations++
		next[key] = flow
		if !connectionsEqual(previous.Connection, connection) {
			events = append(events, Event{Type: EventChanged, At: at, Flow: flow})
		}
	}

	closed := make([]string, 0)
	for key := range s.active {
		if _, exists := next[key]; !exists {
			closed = append(closed, key)
		}
	}
	sort.Strings(closed)
	for _, key := range closed {
		events = append(events, Event{Type: EventClosed, At: at, Flow: s.active[key]})
	}

	previous := s.active
	s.active = next
	s.updateHistory(previous, at)
	return events
}

func (s *Store) Active() []Flow {
	flows := make([]Flow, 0, len(s.active))
	for _, item := range s.active {
		flows = append(flows, item)
	}
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].FirstSeen.Equal(flows[j].FirstSeen) {
			return flows[i].ID < flows[j].ID
		}
		return flows[i].FirstSeen.Before(flows[j].FirstSeen)
	})
	return flows
}

func (s *Store) Stats() Stats {
	stats := Stats{Active: len(s.active)}
	for _, item := range s.active {
		switch item.Connection.Direction {
		case observe.DirectionInbound:
			stats.Inbound++
		case observe.DirectionOutbound:
			stats.Outbound++
		case observe.DirectionListen:
			stats.Listen++
		case observe.DirectionBound:
			stats.Bound++
		default:
			stats.Unknown++
		}
	}
	return stats
}

func (s *Store) History() []Traffic {
	traffic := make([]Traffic, 0, len(s.history))
	for _, item := range s.history {
		traffic = append(traffic, item)
	}
	sort.Slice(traffic, func(i, j int) bool {
		if traffic[i].FirstSeen.Equal(traffic[j].FirstSeen) {
			return traffic[i].ID < traffic[j].ID
		}
		return traffic[i].FirstSeen.Before(traffic[j].FirstSeen)
	})
	return traffic
}

func (s *Store) updateHistory(previous map[string]Flow, at time.Time) {
	for key, item := range s.history {
		item.ActiveSockets = 0
		s.history[key] = item
	}
	flowIDs := make([]string, 0, len(s.active))
	for id := range s.active {
		flowIDs = append(flowIDs, id)
	}
	sort.Strings(flowIDs)
	nextAssignments := make(map[string]string, len(flowIDs))
	for _, flowID := range flowIDs {
		active := s.active[flowID]
		key, assigned := s.assignments[flowID]
		if !assigned {
			key = TrafficKey(active.Connection)
		}
		nextAssignments[flowID] = key
		item, exists := s.history[key]
		if !exists {
			item = Traffic{
				ID:             key,
				LastConnection: active.Connection,
				FirstSeen:      active.FirstSeen,
			}
		}
		item.LastSeen = at
		item.Observations++
		item.ActiveSockets++
		item.SourcePorts = addPort(item.SourcePorts, sourcePort(active.Connection))
		item.LastConnection = mergeTrafficConnection(item.LastConnection, active.Connection)
		if _, wasActive := previous[flowID]; !wasActive {
			item.Connections++
		}
		if item.Connections == 0 {
			item.Connections = 1
		}
		s.history[key] = item
	}
	s.assignments = nextAssignments
}

func TrafficKey(connection observe.Connection) string {
	owner := trafficOwnerKey(connection)
	switch connection.Direction {
	case observe.DirectionInbound:
		return fmt.Sprintf("%s|in|%s|%s|%s", connection.Network, connection.Local.String(), addressString(connection.Remote), owner)
	case observe.DirectionListen, observe.DirectionBound:
		return fmt.Sprintf("%s|%s|%s|%s", connection.Network, connection.Direction, connection.Local.String(), owner)
	default:
		return fmt.Sprintf("%s|%s|%s|%s", connection.Network, connection.Direction, connection.Remote.String(), owner)
	}
}

func trafficOwnerKey(connection observe.Connection) string {
	if len(connection.Owners) == 0 {
		return fmt.Sprintf("uid:%d", connection.UID)
	}
	owner := connection.Owners[0]
	switch {
	case owner.Service != "":
		return "service:" + owner.Service
	case owner.Executable != "":
		return "exe:" + owner.Executable
	case owner.Name != "":
		return fmt.Sprintf("name:%s|user:%s", owner.Name, owner.User)
	default:
		return fmt.Sprintf("pid:%d", owner.PID)
	}
}

func carryAttribution(previous, current observe.Connection) observe.Connection {
	if len(current.Owners) == 0 && len(previous.Owners) > 0 {
		current.Owners = slices.Clone(previous.Owners)
	}
	if strings.HasPrefix(current.Network, "tcp") &&
		(previous.Direction == observe.DirectionInbound || previous.Direction == observe.DirectionOutbound) &&
		current.Direction != observe.DirectionListen {
		current.Direction = previous.Direction
	}
	return current
}

func mergeTrafficConnection(previous, current observe.Connection) observe.Connection {
	current.Owners = mergeOwners(previous.Owners, current.Owners)
	return current
}

func sourcePort(connection observe.Connection) uint16 {
	if connection.Direction == observe.DirectionInbound {
		return connection.Remote.Port
	}
	return connection.Local.Port
}

func addPort(ports []uint16, port uint16) []uint16 {
	if port == 0 {
		return ports
	}
	index, found := slices.BinarySearch(ports, port)
	if found {
		return ports
	}
	ports = append(ports, 0)
	copy(ports[index+1:], ports[index:])
	ports[index] = port
	return ports
}

func addressString(endpoint observe.Endpoint) string {
	if !endpoint.Address.IsValid() || endpoint.Address.IsUnspecified() {
		return "*"
	}
	return endpoint.Address.String()
}

func aggregate(connections []observe.Connection) map[string]observe.Connection {
	result := make(map[string]observe.Connection, len(connections))
	for _, connection := range connections {
		normalize(&connection)
		key := Key(connection)
		if existing, found := result[key]; found {
			existing.Owners = mergeOwners(existing.Owners, connection.Owners)
			existing.SocketInodes = uniqueSorted(append(existing.SocketInodes, connection.SocketInodes...))
			result[key] = existing
			continue
		}
		result[key] = connection
	}
	return result
}

func normalize(connection *observe.Connection) {
	connection.SocketInodes = uniqueSorted(connection.SocketInodes)
	sort.Slice(connection.Owners, func(i, j int) bool {
		if connection.Owners[i].PID == connection.Owners[j].PID {
			return connection.Owners[i].Name < connection.Owners[j].Name
		}
		return connection.Owners[i].PID < connection.Owners[j].PID
	})
	connection.Owners = slices.CompactFunc(connection.Owners, func(a, b observe.Process) bool {
		return a.PID == b.PID
	})
}

func mergeOwners(a, b []observe.Process) []observe.Process {
	owners := append(slices.Clone(a), b...)
	sort.Slice(owners, func(i, j int) bool { return owners[i].PID < owners[j].PID })
	return slices.CompactFunc(owners, func(left, right observe.Process) bool {
		return left.PID == right.PID
	})
}

func uniqueSorted(values []string) []string {
	values = slices.Clone(values)
	sort.Strings(values)
	return slices.Compact(values)
}

func connectionsEqual(a, b observe.Connection) bool {
	if a.Network != b.Network || a.Local != b.Local || a.Remote != b.Remote ||
		a.State != b.State || a.Direction != b.Direction || a.UID != b.UID {
		return false
	}
	if !slices.Equal(a.SocketInodes, b.SocketInodes) || len(a.Owners) != len(b.Owners) {
		return false
	}
	for i := range a.Owners {
		if a.Owners[i] != b.Owners[i] {
			return false
		}
	}
	return true
}

func ProcessLabel(connection observe.Connection) string {
	if len(connection.Owners) == 0 {
		return "unattributed"
	}
	owner := connection.Owners[0]
	name := strings.TrimSpace(owner.Name)
	if name == "" {
		name = "pid"
	}
	label := fmt.Sprintf("%s(%d)", name, owner.PID)
	if len(connection.Owners) > 1 {
		label += fmt.Sprintf(" +%d", len(connection.Owners)-1)
	}
	return label
}
