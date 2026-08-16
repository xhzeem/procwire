package dnsmon

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

func TestStoreRetainsExpiredDNSHistory(t *testing.T) {
	store := NewStore()
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	question := Question{Name: "example.com", Type: "A", Class: 1}
	store.Apply(Event{
		CapturedAt:  now,
		Direction:   DirectionQuery,
		Questions:   []Question{question},
		Destination: observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 53},
	})
	store.Apply(Event{
		CapturedAt: now.Add(time.Second),
		Direction:  DirectionResponse,
		Questions:  []Question{question},
		Answers: []Answer{{
			Name: "example.com", Type: "A", Class: 1, TTL: 60, Value: "1.2.3.4", Section: "answer",
		}},
		Source: observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 53},
	})

	entries := store.Entries(now.Add(30 * time.Second))
	if len(entries) != 1 || entries[0].Queries != 1 || entries[0].Responses != 1 || !entries[0].Cached {
		t.Fatalf("active cache entry = %#v", entries)
	}
	if names := store.Hostnames(netip.MustParseAddr("1.2.3.4"), now.Add(30*time.Second)); len(names) != 1 || names[0] != "example.com" {
		t.Fatalf("reverse names = %#v", names)
	}
	entries = store.Entries(now.Add(2 * time.Minute))
	if len(entries) != 1 || entries[0].Cached {
		t.Fatalf("expired entry did not remain as history: %#v", entries)
	}
}

func TestSeedHosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost local.test\n::1 localhost6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore()
	if err := store.SeedHosts(path, time.Now()); err != nil {
		t.Fatal(err)
	}
	entries := store.Entries(time.Now().Add(24 * time.Hour))
	if len(entries) != 3 {
		t.Fatalf("host entries = %#v", entries)
	}
	for _, entry := range entries {
		if !entry.Cached || entry.Source != "hosts" || len(entry.Answers) != 1 || !entry.Answers[0].Permanent {
			t.Fatalf("invalid hosts entry: %#v", entry)
		}
	}
}
