package observe

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type rawSocket struct {
	connection Connection
	inode      string
}

func parseSocketTable(network string, data []byte) ([]rawSocket, error) {
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0
	sockets := make([]rawSocket, 0)
	for scanner.Scan() {
		lineNumber++
		if lineNumber == 1 {
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, fmt.Errorf("%s line %d: expected at least 10 fields", network, lineNumber)
		}
		local, err := parseProcEndpoint(fields[1], strings.HasSuffix(network, "6"))
		if err != nil {
			return nil, fmt.Errorf("%s line %d local endpoint: %w", network, lineNumber, err)
		}
		remote, err := parseProcEndpoint(fields[2], strings.HasSuffix(network, "6"))
		if err != nil {
			return nil, fmt.Errorf("%s line %d remote endpoint: %w", network, lineNumber, err)
		}
		uid, err := strconv.Atoi(fields[7])
		if err != nil {
			return nil, fmt.Errorf("%s line %d uid: %w", network, lineNumber, err)
		}
		inode := fields[9]
		connection := Connection{
			Network: network,
			Local:   local,
			Remote:  remote,
			State:   socketState(network, fields[3]),
			UID:     uid,
		}
		if inode != "0" {
			connection.SocketInodes = []string{inode}
		}
		sockets = append(sockets, rawSocket{connection: connection, inode: inode})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s socket table: %w", network, err)
	}
	return sockets, nil
}

func parseProcEndpoint(value string, ipv6 bool) (Endpoint, error) {
	addressHex, portHex, found := strings.Cut(value, ":")
	if !found {
		return Endpoint{}, fmt.Errorf("invalid endpoint %q", value)
	}
	addressBytes, err := hex.DecodeString(addressHex)
	if err != nil {
		return Endpoint{}, fmt.Errorf("decode address: %w", err)
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return Endpoint{}, fmt.Errorf("decode port: %w", err)
	}

	var address netip.Addr
	if ipv6 {
		if len(addressBytes) != 16 {
			return Endpoint{}, fmt.Errorf("expected 16 address bytes, got %d", len(addressBytes))
		}
		for start := 0; start < len(addressBytes); start += 4 {
			reverse(addressBytes[start : start+4])
		}
		var raw [16]byte
		copy(raw[:], addressBytes)
		address = netip.AddrFrom16(raw).Unmap()
	} else {
		if len(addressBytes) != 4 {
			return Endpoint{}, fmt.Errorf("expected 4 address bytes, got %d", len(addressBytes))
		}
		reverse(addressBytes)
		var raw [4]byte
		copy(raw[:], addressBytes)
		address = netip.AddrFrom4(raw)
	}
	return Endpoint{Address: address, Port: uint16(port)}, nil
}

func reverse(value []byte) {
	for left, right := 0, len(value)-1; left < right; left, right = left+1, right-1 {
		value[left], value[right] = value[right], value[left]
	}
}

func socketState(network, code string) string {
	if strings.HasPrefix(network, "udp") {
		switch code {
		case "01":
			return "ESTABLISHED"
		case "07":
			return "UNCONNECTED"
		}
	}
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
		"0C": "NEW_SYN_RECV",
	}
	if state, found := states[code]; found {
		return state
	}
	return "0x" + code
}

func inferDirections(connections []Connection) {
	listeners := make([]Connection, 0)
	for i := range connections {
		if strings.HasPrefix(connections[i].Network, "tcp") && connections[i].State == "LISTEN" {
			connections[i].Direction = DirectionListen
			listeners = append(listeners, connections[i])
			continue
		}
		if strings.HasPrefix(connections[i].Network, "udp") && connections[i].Remote.IsWildcard() && connections[i].Remote.Port == 0 {
			connections[i].Direction = DirectionBound
			continue
		}
		connections[i].Direction = DirectionUnknown
	}
	for i := range connections {
		connection := &connections[i]
		if !strings.HasPrefix(connection.Network, "tcp") || connection.Direction == DirectionListen {
			continue
		}
		if hasListener(*connection, listeners) {
			connection.Direction = DirectionInbound
		} else {
			connection.Direction = DirectionOutbound
		}
	}
}

func hasListener(connection Connection, listeners []Connection) bool {
	for _, listener := range listeners {
		if listener.Network != connection.Network || listener.Local.Port != connection.Local.Port {
			continue
		}
		if listener.Local.IsWildcard() || listener.Local.Address == connection.Local.Address {
			return true
		}
	}
	return false
}
