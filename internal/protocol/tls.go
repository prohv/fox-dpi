package protocol

import (
	"encoding/binary"
	"fmt"
)

// TLSDissector parses unencrypted TLS ClientHello handshakes to extract SNI hostnames.
type TLSDissector struct{}

func NewTLSDissector() *TLSDissector {
	return &TLSDissector{}
}

func (d *TLSDissector) Name() string {
	return "TLS"
}

// Inspect parses record and handshake headers, skips length vectors, and decodes SNI TLVs.
func (d *TLSDissector) Inspect(payload []byte) (Verdict, Metadata, error) {
	// Must have at least TLS record header (5 bytes) + Handshake header (4 bytes)
	if len(payload) < 9 {
		if len(payload) >= 1 && payload[0] == 0x16 {
			return VerdictNeedMoreData, Metadata{}, nil
		}
		return VerdictUnknown, Metadata{}, nil
	}

	// Byte 0 must be Handshake (0x16) and Byte 1 must be SSL 3.0 / TLS 1.X (0x03)
	if payload[0] != 0x16 || payload[1] != 0x03 {
		return VerdictUnknown, Metadata{}, nil
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return VerdictNeedMoreData, Metadata{}, nil
	}

	// Byte 5 must be HandshakeType ClientHello (0x01)
	if payload[5] != 0x01 {
		return VerdictUnknown, Metadata{}, nil
	}

	clientVerMajor := payload[9]
	clientVerMinor := payload[10]

	// Offset at start of Session ID (byte 43)
	offset := 43
	if offset >= len(payload) {
		return VerdictNeedMoreData, Metadata{}, nil
	}

	// Skip Session ID
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen
	if offset+2 > len(payload) {
		return VerdictNeedMoreData, Metadata{}, nil
	}

	// Skip Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset+1 > len(payload) {
		return VerdictNeedMoreData, Metadata{}, nil
	}

	// Skip Compression Methods
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen
	if offset+2 > len(payload) {
		// No extensions present
		return VerdictUnknown, Metadata{}, nil
	}

	// Parse Extensions TLV
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(payload) {
		return VerdictNeedMoreData, Metadata{}, nil
	}

	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd {
			return VerdictNeedMoreData, Metadata{}, nil
		}

		// Extension 0x0000: Server Name Indication (SNI)
		if extType == 0x0000 {
			if extLen < 5 {
				return VerdictUnknown, Metadata{}, ErrMalformedData
			}
			// Skip Server Name List length (2 bytes)
			// Server Name Type must be host_name (0x00)
			nameType := payload[offset+2]
			if nameType != 0x00 {
				return VerdictUnknown, Metadata{}, ErrMalformedData
			}

			nameLen := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
			if offset+5+nameLen > offset+extLen {
				return VerdictNeedMoreData, Metadata{}, nil
			}

			serverName := string(payload[offset+5 : offset+5+nameLen])
			versionStr := fmt.Sprintf("TLS 1.%d", clientVerMinor-1)
			if clientVerMajor == 3 && clientVerMinor == 3 {
				versionStr = "TLS 1.2/1.3"
			}

			return VerdictMatched, Metadata{
				Protocol: "TLS",
				Host:     serverName,
				Details: map[string]string{
					"sni":     serverName,
					"version": versionStr,
				},
			}, nil
		}

		offset += extLen
	}

	return VerdictUnknown, Metadata{}, nil
}
