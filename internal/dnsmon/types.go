package dnsmon

import (
	"net/netip"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

type Direction string

const (
	DirectionQuery    Direction = "query"
	DirectionResponse Direction = "response"
)

type Packet struct {
	CapturedAt  time.Time        `json:"captured_at"`
	Protocol    string           `json:"protocol"`
	Source      observe.Endpoint `json:"source"`
	Destination observe.Endpoint `json:"destination"`
	Process     observe.Process  `json:"process"`
	UID         uint32           `json:"uid"`
	GID         uint32           `json:"gid"`
	CgroupID    uint64           `json:"cgroup_id"`
	Payload     []byte           `json:"payload,omitempty"`
}

type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class uint16 `json:"class"`
}

type Answer struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Class   uint16 `json:"class"`
	TTL     uint32 `json:"ttl"`
	Value   string `json:"value"`
	Section string `json:"section"`
}

type Event struct {
	CapturedAt    time.Time        `json:"captured_at"`
	Direction     Direction        `json:"direction"`
	Protocol      string           `json:"protocol"`
	TransactionID uint16           `json:"transaction_id"`
	RCode         string           `json:"rcode"`
	Authoritative bool             `json:"authoritative"`
	Truncated     bool             `json:"truncated"`
	Questions     []Question       `json:"questions,omitempty"`
	Answers       []Answer         `json:"answers,omitempty"`
	Source        observe.Endpoint `json:"source"`
	Destination   observe.Endpoint `json:"destination"`
	Process       observe.Process  `json:"process"`
	UID           uint32           `json:"uid"`
	GID           uint32           `json:"gid"`
	CgroupID      uint64           `json:"cgroup_id"`
}

type CachedAnswer struct {
	Value     string    `json:"value"`
	TTL       uint32    `json:"ttl"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Permanent bool      `json:"permanent,omitempty"`
}

type Entry struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Type      string           `json:"type"`
	Source    string           `json:"source"`
	Answers   []CachedAnswer   `json:"answers,omitempty"`
	Queries   uint64           `json:"queries"`
	Responses uint64           `json:"responses"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
	LastRCode string           `json:"last_rcode,omitempty"`
	Process   observe.Process  `json:"process"`
	Server    observe.Endpoint `json:"server"`
	Cached    bool             `json:"cached"`
	ExpiresAt time.Time        `json:"expires_at,omitempty"`
}

func (entry Entry) Addresses(now time.Time) []netip.Addr {
	addresses := make([]netip.Addr, 0)
	for _, answer := range entry.Answers {
		if !answer.Permanent && !answer.ExpiresAt.After(now) {
			continue
		}
		address, err := netip.ParseAddr(answer.Value)
		if err == nil {
			addresses = append(addresses, address.Unmap())
		}
	}
	return addresses
}
