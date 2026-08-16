package dnsmon

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/xhzeem/procwire/internal/observe"
)

func TestParseQueryAndResponse(t *testing.T) {
	query := dnsQuery("example.com")
	packet := Packet{
		CapturedAt:  time.Now(),
		Protocol:    "udp",
		Source:      observe.Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 53000},
		Destination: observe.Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 53},
		Payload:     query,
	}
	events, err := Parse(packet)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if len(events) != 1 || events[0].Direction != DirectionQuery || len(events[0].Questions) != 1 {
		t.Fatalf("query events = %#v", events)
	}
	if events[0].Questions[0].Name != "example.com" || events[0].Questions[0].Type != "A" {
		t.Fatalf("question = %#v", events[0].Questions[0])
	}

	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		1, 2, 3, 4,
	)
	packet.Payload = response
	packet.Source, packet.Destination = packet.Destination, packet.Source
	events, err = Parse(packet)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(events) != 1 || events[0].Direction != DirectionResponse || len(events[0].Answers) != 1 {
		t.Fatalf("response events = %#v", events)
	}
	answer := events[0].Answers[0]
	if answer.Name != "example.com" || answer.Value != "1.2.3.4" || answer.TTL != 60 {
		t.Fatalf("answer = %#v", answer)
	}
}

func TestParseTCPFraming(t *testing.T) {
	query := dnsQuery("example.com")
	payload := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(payload, uint16(len(query)))
	payload = append(payload, query...)
	events, err := Parse(Packet{Protocol: "tcp", Payload: payload})
	if err != nil || len(events) != 1 {
		t.Fatalf("parse TCP DNS: events=%#v err=%v", events, err)
	}
}

func dnsQuery(name string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x5057)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	for _, label := range []string{"example", "com"} {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	return query
}
