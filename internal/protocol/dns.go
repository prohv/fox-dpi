package protocol

import (
	"encoding/binary"
	"fmt"
)

// DNSDissector parses DNS queries and responses without heap allocations in the hot path.
type DNSDissector struct{}

func NewDNSDissector() *DNSDissector {
	return &DNSDissector{}
}

func (d *DNSDissector) Name() string {
	return "DNS"
}

// Inspect parses DNS header flags, extracts the primary QNAME domain, and decodes query types.
func (d *DNSDissector) Inspect(payload []byte) (Verdict, Metadata, error) {
	if len(payload) < 12 {
		return VerdictUnknown, Metadata{}, nil
	}

	flags := binary.BigEndian.Uint16(payload[2:4])
	qdCount := binary.BigEndian.Uint16(payload[4:6])

	// Must have at least one question record to extract a target domain
	if qdCount == 0 {
		return VerdictUnknown, Metadata{}, nil
	}

	isResponse := (flags & 0x8000) != 0
	opcode := (flags >> 11) & 0x0F
	if opcode != 0 { // Standard query only
		return VerdictUnknown, Metadata{}, nil
	}

	offset := 12
	var nameBuf [256]byte
	nameLen := 0
	jumpCount := 0

	for {
		if offset >= len(payload) {
			return VerdictNeedMoreData, Metadata{}, nil
		}

		length := int(payload[offset])
		if length == 0 {
			offset++
			break
		}

		// Handle DNS compression pointer (0b11xxxxxx)
		if (length & 0xC0) == 0xC0 {
			if offset+1 >= len(payload) {
				return VerdictNeedMoreData, Metadata{}, nil
			}
			ptrOffset := int(binary.BigEndian.Uint16(payload[offset:offset+2]) & 0x3FFF)
			offset += 2
			if jumpCount > 5 || ptrOffset >= len(payload) {
				return VerdictUnknown, Metadata{}, ErrMalformedData
			}
			offset = ptrOffset
			jumpCount++
			continue
		}

		offset++
		if offset+length > len(payload) {
			return VerdictNeedMoreData, Metadata{}, nil
		}

		if nameLen > 0 && nameLen < 255 {
			nameBuf[nameLen] = '.'
			nameLen++
		}
		if nameLen+length <= 255 {
			copy(nameBuf[nameLen:], payload[offset:offset+length])
			nameLen += length
		}
		offset += length
	}

	if nameLen == 0 {
		return VerdictUnknown, Metadata{}, nil
	}

	domain := string(nameBuf[:nameLen])

	var qTypeStr string
	if offset+2 <= len(payload) {
		qType := binary.BigEndian.Uint16(payload[offset : offset+2])
		qTypeStr = dnsTypeToString(qType)
	}

	role := "query"
	if isResponse {
		role = "response"
	}

	return VerdictMatched, Metadata{
		Protocol: "DNS",
		Host:     domain,
		Details: map[string]string{
			"role":  role,
			"qtype": qTypeStr,
		},
	}, nil
}

func dnsTypeToString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 12:
		return "PTR"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}
