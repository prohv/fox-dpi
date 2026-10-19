package protocol

import (
	"bytes"
	"strconv"
)

// Dispatcher coordinates protocol parsers using fast magic-byte prefix matching.
type Dispatcher struct {
	dns  *DNSDissector
	tls  *TLSDissector
	http *HTTPDissector
}

// NewDispatcher initializes standard dissectors.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{
		dns:  NewDNSDissector(),
		tls:  NewTLSDissector(),
		http: NewHTTPDissector(),
	}
}

// Dispatch routes the payload to the matching dissector based on transport protocol and magic bytes.
func (d *Dispatcher) Dispatch(payload []byte, proto uint8) (Verdict, Metadata, error) {
	if len(payload) == 0 {
		return VerdictUnknown, Metadata{}, nil
	}

	// UDP Path: Evaluate DNS
	if proto == 17 {
		return d.dns.Inspect(payload)
	}

	// TCP Path: Evaluate TLS and HTTP via magic prefix
	if proto == 6 {
		// 1. Fast-Path: Zero-offset check (99% of normal traffic, 1-cycle check)
		if payload[0] == 0x16 {
			if len(payload) >= 2 && payload[1] == 0x03 {
				return d.tls.Inspect(payload)
			}
			return VerdictNeedMoreData, Metadata{}, nil
		}

		if isHTTPPrefix(payload) {
			return d.http.Inspect(payload)
		}

		// 2. Sliding-Window Scan (Bounded to 64 bytes) for Padding Evasion Defense (MITRE T1001.003)
		limit := len(payload)
		if limit > 64 {
			limit = 64
		}
		if limit >= 2 {
			window := payload[:limit]

			// Fast search for TLS magic bytes 0x16 0x03
			if idx := bytes.Index(window, []byte{0x16, 0x03}); idx != -1 {
				v, m, err := d.tls.Inspect(payload[idx:])
				if v == VerdictMatched {
					if m.Details == nil {
						m.Details = make(map[string]string)
					}
					m.Details["padding_offset"] = strconv.Itoa(idx)
					return v, m, err
				} else if v == VerdictNeedMoreData {
					return v, m, err
				}
			}

			// Fast search for HTTP verbs
			for i := 1; i <= limit-4; i++ {
				if isHTTPPrefix(payload[i:]) {
					v, m, err := d.http.Inspect(payload[i:])
					if v == VerdictMatched {
						if m.Details == nil {
							m.Details = make(map[string]string)
						}
						m.Details["padding_offset"] = strconv.Itoa(i)
						return v, m, err
					} else if v == VerdictNeedMoreData {
						return v, m, err
					}
				}
			}
		}
	}

	return VerdictUnknown, Metadata{}, nil
}

func isHTTPPrefix(data []byte) bool {
	if len(data) < 3 {
		return false
	}
	switch data[0] {
	case 'G': // GET
		return len(data) >= 4 && data[1] == 'E' && data[2] == 'T' && data[3] == ' '
	case 'P': // POST, PUT, PATCH
		if len(data) >= 4 && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' {
			return true
		}
		if len(data) >= 4 && data[1] == 'U' && data[2] == 'T' && data[3] == ' ' {
			return true
		}
		if len(data) >= 5 && data[1] == 'A' && data[2] == 'T' && data[3] == 'C' && data[4] == 'H' {
			return true
		}
	case 'D': // DELETE
		return len(data) >= 6 && data[1] == 'E' && data[2] == 'L' && data[3] == 'E' && data[4] == 'T' && data[5] == 'E'
	case 'H': // HEAD
		return len(data) >= 4 && data[1] == 'E' && data[2] == 'A' && data[3] == 'D'
	}
	return false
}
