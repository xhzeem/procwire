package dnsmon

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

var errIncompleteDNS = errors.New("incomplete DNS message")

func Parse(packet Packet) ([]Event, error) {
	if packet.Protocol != "tcp" {
		event, err := parseMessage(packet, packet.Payload)
		if err != nil {
			return nil, err
		}
		return []Event{event}, nil
	}

	payload := packet.Payload
	events := make([]Event, 0, 1)
	for len(payload) >= 2 {
		length := int(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
		if length == 0 {
			continue
		}
		if length > len(payload) {
			return events, errIncompleteDNS
		}
		event, err := parseMessage(packet, payload[:length])
		if err != nil {
			return events, err
		}
		events = append(events, event)
		payload = payload[length:]
	}
	if len(events) == 0 {
		return nil, errIncompleteDNS
	}
	return events, nil
}

func parseMessage(packet Packet, data []byte) (Event, error) {
	if len(data) < 12 {
		return Event{}, errIncompleteDNS
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	event := Event{
		CapturedAt:    packet.CapturedAt,
		Direction:     DirectionQuery,
		Protocol:      packet.Protocol,
		TransactionID: binary.BigEndian.Uint16(data[0:2]),
		RCode:         rcodeName(flags & 0x000f),
		Authoritative: flags&0x0400 != 0,
		Truncated:     flags&0x0200 != 0,
		Source:        packet.Source,
		Destination:   packet.Destination,
		Process:       packet.Process,
		UID:           packet.UID,
		GID:           packet.GID,
		CgroupID:      packet.CgroupID,
	}
	if flags&0x8000 != 0 {
		event.Direction = DirectionResponse
	}
	counts := [4]int{
		int(binary.BigEndian.Uint16(data[4:6])),
		int(binary.BigEndian.Uint16(data[6:8])),
		int(binary.BigEndian.Uint16(data[8:10])),
		int(binary.BigEndian.Uint16(data[10:12])),
	}
	offset := 12
	for range counts[0] {
		name, next, err := readName(data, offset)
		if err != nil || next+4 > len(data) {
			return Event{}, errIncompleteDNS
		}
		event.Questions = append(event.Questions, Question{
			Name:  normalizeName(name),
			Type:  typeName(binary.BigEndian.Uint16(data[next : next+2])),
			Class: binary.BigEndian.Uint16(data[next+2 : next+4]),
		})
		offset = next + 4
	}
	sections := []string{"answer", "authority", "additional"}
	for sectionIndex, count := range counts[1:] {
		for range count {
			answer, next, err := readAnswer(data, offset, sections[sectionIndex])
			if err != nil {
				return Event{}, err
			}
			event.Answers = append(event.Answers, answer)
			offset = next
		}
	}
	return event, nil
}

func readAnswer(data []byte, offset int, section string) (Answer, int, error) {
	name, next, err := readName(data, offset)
	if err != nil || next+10 > len(data) {
		return Answer{}, 0, errIncompleteDNS
	}
	recordType := binary.BigEndian.Uint16(data[next : next+2])
	class := binary.BigEndian.Uint16(data[next+2 : next+4])
	ttl := binary.BigEndian.Uint32(data[next+4 : next+8])
	length := int(binary.BigEndian.Uint16(data[next+8 : next+10]))
	rdata := next + 10
	end := rdata + length
	if length < 0 || end > len(data) {
		return Answer{}, 0, errIncompleteDNS
	}
	value, err := answerValue(data, rdata, length, recordType)
	if err != nil {
		return Answer{}, 0, err
	}
	return Answer{
		Name:    normalizeName(name),
		Type:    typeName(recordType),
		Class:   class,
		TTL:     ttl,
		Value:   value,
		Section: section,
	}, end, nil
}

func answerValue(data []byte, offset, length int, recordType uint16) (string, error) {
	value := data[offset : offset+length]
	switch recordType {
	case 1:
		if len(value) != 4 {
			return "", errIncompleteDNS
		}
		var raw [4]byte
		copy(raw[:], value)
		return netip.AddrFrom4(raw).String(), nil
	case 28:
		if len(value) != 16 {
			return "", errIncompleteDNS
		}
		var raw [16]byte
		copy(raw[:], value)
		return netip.AddrFrom16(raw).String(), nil
	case 2, 5, 12:
		name, _, err := readName(data, offset)
		return normalizeName(name), err
	case 15:
		if length < 3 {
			return "", errIncompleteDNS
		}
		name, _, err := readName(data, offset+2)
		return fmt.Sprintf("%d %s", binary.BigEndian.Uint16(value[:2]), normalizeName(name)), err
	case 16:
		parts := make([]string, 0)
		for cursor := 0; cursor < len(value); {
			size := int(value[cursor])
			cursor++
			if cursor+size > len(value) {
				return "", errIncompleteDNS
			}
			parts = append(parts, strconv.QuoteToASCII(string(value[cursor:cursor+size])))
			cursor += size
		}
		return strings.Join(parts, " "), nil
	case 33:
		if length < 7 {
			return "", errIncompleteDNS
		}
		name, _, err := readName(data, offset+6)
		return fmt.Sprintf("%d %d %d %s", binary.BigEndian.Uint16(value[:2]), binary.BigEndian.Uint16(value[2:4]), binary.BigEndian.Uint16(value[4:6]), normalizeName(name)), err
	default:
		if len(value) > 64 {
			value = value[:64]
		}
		return hex.EncodeToString(value), nil
	}
}

func readName(data []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(data) {
		return "", 0, errIncompleteDNS
	}
	labels := make([]string, 0, 4)
	cursor := offset
	next := -1
	visited := make(map[int]struct{})
	for steps := 0; steps < 128; steps++ {
		if cursor >= len(data) {
			return "", 0, errIncompleteDNS
		}
		length := int(data[cursor])
		if length == 0 {
			cursor++
			if next < 0 {
				next = cursor
			}
			return strings.Join(labels, "."), next, nil
		}
		if length&0xc0 == 0xc0 {
			if cursor+1 >= len(data) {
				return "", 0, errIncompleteDNS
			}
			pointer := (length&0x3f)<<8 | int(data[cursor+1])
			if pointer >= len(data) {
				return "", 0, errIncompleteDNS
			}
			if _, exists := visited[pointer]; exists {
				return "", 0, errors.New("DNS compression pointer loop")
			}
			visited[pointer] = struct{}{}
			if next < 0 {
				next = cursor + 2
			}
			cursor = pointer
			continue
		}
		if length&0xc0 != 0 || length > 63 || cursor+1+length > len(data) {
			return "", 0, errIncompleteDNS
		}
		labels = append(labels, string(data[cursor+1:cursor+1+length]))
		cursor += 1 + length
	}
	return "", 0, errors.New("DNS name exceeds compression limit")
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func typeName(value uint16) string {
	switch value {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 41:
		return "OPT"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", value)
	}
}

func rcodeName(value uint16) string {
	switch value {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", value)
	}
}
