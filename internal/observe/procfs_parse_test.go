package observe

import (
	"net/netip"
	"testing"
)

func TestParseSocketTableIPv4(t *testing.T) {
	data := []byte("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0\n")

	sockets, err := parseSocketTable("tcp4", data)
	if err != nil {
		t.Fatalf("parse socket table: %v", err)
	}
	if len(sockets) != 1 {
		t.Fatalf("got %d sockets, want 1", len(sockets))
	}
	connection := sockets[0].connection
	if connection.Local.Address != netip.MustParseAddr("127.0.0.1") || connection.Local.Port != 8080 {
		t.Fatalf("unexpected local endpoint: %s", connection.Local)
	}
	if connection.State != "LISTEN" || sockets[0].inode != "12345" || connection.UID != 1000 {
		t.Fatalf("unexpected parsed socket: %#v", sockets[0])
	}
}

func TestParseProcEndpointIPv6MappedAddress(t *testing.T) {
	endpoint, err := parseProcEndpoint("0000000000000000FFFF00000100007F:0035", true)
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	if endpoint.Address != netip.MustParseAddr("127.0.0.1") || endpoint.Port != 53 {
		t.Fatalf("unexpected endpoint: %s", endpoint)
	}
}

func TestInferDirections(t *testing.T) {
	connections := []Connection{
		{Network: "tcp4", Local: Endpoint{Address: netip.IPv4Unspecified(), Port: 443}, State: "LISTEN"},
		{Network: "tcp4", Local: Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 443}, Remote: Endpoint{Address: netip.MustParseAddr("10.0.0.3"), Port: 53000}, State: "ESTABLISHED"},
		{Network: "tcp4", Local: Endpoint{Address: netip.MustParseAddr("10.0.0.2"), Port: 53001}, Remote: Endpoint{Address: netip.MustParseAddr("1.1.1.1"), Port: 443}, State: "ESTABLISHED"},
		{Network: "udp4", Local: Endpoint{Address: netip.IPv4Unspecified(), Port: 53}, Remote: Endpoint{Address: netip.IPv4Unspecified()}, State: "UNCONNECTED"},
	}

	inferDirections(connections)
	want := []Direction{DirectionListen, DirectionInbound, DirectionOutbound, DirectionBound}
	for index := range want {
		if connections[index].Direction != want[index] {
			t.Errorf("connection %d direction = %q, want %q", index, connections[index].Direction, want[index])
		}
	}
}

func TestWildcardEndpointString(t *testing.T) {
	if got := (Endpoint{}).String(); got != "*:*" {
		t.Fatalf("wildcard endpoint = %q, want *:*", got)
	}
}
