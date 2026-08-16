package dnsmon

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

type storedEntry struct {
	entry   Entry
	answers map[string]CachedAnswer
}

type Store struct {
	entries map[string]*storedEntry
	pending map[string]pendingQuery
}

type pendingQuery struct {
	process  observe.Process
	uid      uint32
	gid      uint32
	cgroupID uint64
	seenAt   time.Time
}

func NewStore() *Store {
	return &Store{
		entries: make(map[string]*storedEntry),
		pending: make(map[string]pendingQuery),
	}
}

func (store *Store) SeedHosts(path string, now time.Time) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		address, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		recordType := "A"
		if address.Is6() {
			recordType = "AAAA"
		}
		for _, name := range fields[1:] {
			entry := store.get(normalizeName(name), recordType, now)
			entry.entry.Source = "hosts"
			entry.answers[address.String()] = CachedAnswer{
				Value:     address.String(),
				LastSeen:  now,
				Permanent: true,
			}
		}
	}
	return scanner.Err()
}

func (store *Store) Apply(event Event) Event {
	at := event.CapturedAt
	if at.IsZero() {
		at = time.Now()
	}
	event.CapturedAt = at
	key := transactionKey(event)
	if event.Direction == DirectionQuery {
		store.pending[key] = pendingQuery{
			process: event.Process, uid: event.UID, gid: event.GID, cgroupID: event.CgroupID, seenAt: at,
		}
	} else if pending, found := store.pending[key]; found {
		if event.Process.PID == 0 {
			event.Process = pending.process
			event.UID = pending.uid
			event.GID = pending.gid
			event.CgroupID = pending.cgroupID
		}
		delete(store.pending, key)
	}
	store.expirePending(at)
	for _, question := range event.Questions {
		entry := store.get(question.Name, question.Type, at)
		entry.entry.LastSeen = at
		entry.entry.Process = event.Process
		entry.entry.LastRCode = event.RCode
		entry.entry.Server = dnsServer(event)
		if event.Direction == DirectionQuery {
			entry.entry.Queries++
		} else {
			entry.entry.Responses++
		}
	}
	for _, answer := range event.Answers {
		if answer.Section == "authority" || answer.Type == "OPT" || answer.Name == "" {
			continue
		}
		entry := store.get(answer.Name, answer.Type, at)
		entry.entry.LastSeen = at
		entry.entry.Process = event.Process
		entry.entry.LastRCode = event.RCode
		entry.entry.Server = dnsServer(event)
		entry.entry.Source = "observed"
		entry.answers[answer.Value] = CachedAnswer{
			Value:     answer.Value,
			TTL:       answer.TTL,
			LastSeen:  at,
			ExpiresAt: at.Add(time.Duration(answer.TTL) * time.Second),
		}
	}
	return event
}

func (store *Store) Entries(now time.Time) []Entry {
	entries := make([]Entry, 0, len(store.entries))
	for _, stored := range store.entries {
		entry := stored.entry
		entry.Answers = entry.Answers[:0]
		entry.Cached = false
		entry.ExpiresAt = time.Time{}
		for _, answer := range stored.answers {
			entry.Answers = append(entry.Answers, answer)
			if answer.Permanent || answer.ExpiresAt.After(now) {
				entry.Cached = true
				if !answer.Permanent && answer.ExpiresAt.After(entry.ExpiresAt) {
					entry.ExpiresAt = answer.ExpiresAt
				}
			}
		}
		sort.Slice(entry.Answers, func(i, j int) bool { return entry.Answers[i].Value < entry.Answers[j].Value })
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].LastSeen.Equal(entries[j].LastSeen) {
			return entries[i].ID < entries[j].ID
		}
		return entries[i].LastSeen.After(entries[j].LastSeen)
	})
	return entries
}

func (store *Store) Hostnames(address netip.Addr, now time.Time) []string {
	address = address.Unmap()
	names := make([]string, 0)
	for _, entry := range store.Entries(now) {
		if entry.Type != "A" && entry.Type != "AAAA" {
			continue
		}
		for _, candidate := range entry.Addresses(now) {
			if candidate == address {
				names = append(names, entry.Name)
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func (store *Store) get(name, recordType string, now time.Time) *storedEntry {
	name = normalizeName(name)
	key := fmt.Sprintf("%s|%s", name, recordType)
	if entry := store.entries[key]; entry != nil {
		return entry
	}
	entry := &storedEntry{
		entry: Entry{
			ID:        key,
			Name:      name,
			Type:      recordType,
			Source:    "observed",
			FirstSeen: now,
			LastSeen:  now,
		},
		answers: make(map[string]CachedAnswer),
	}
	store.entries[key] = entry
	return entry
}

func dnsServer(event Event) observe.Endpoint {
	if event.Direction == DirectionQuery {
		return event.Destination
	}
	return event.Source
}

func transactionKey(event Event) string {
	client := event.Source
	server := event.Destination
	if event.Direction == DirectionResponse {
		client, server = event.Destination, event.Source
	}
	return fmt.Sprintf("%s|%d|%s|%s", event.Protocol, event.TransactionID, client.String(), server.String())
}

func (store *Store) expirePending(now time.Time) {
	if len(store.pending) < 4096 {
		return
	}
	cutoff := now.Add(-2 * time.Minute)
	for key, pending := range store.pending {
		if pending.seenAt.Before(cutoff) {
			delete(store.pending, key)
		}
	}
}
