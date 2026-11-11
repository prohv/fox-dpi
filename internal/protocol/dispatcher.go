package protocol

import (
	"bytes"
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

		if v, m, err := d.http.Inspect(payload); v != VerdictUnknown {
			return v, m, err
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
					m.PaddingOffset = idx
					return v, m, err
				} else if v == VerdictNeedMoreData {
					return v, m, err
				}
			}

			// Fast search for HTTP verbs
			for i := 1; i <= limit-4; i++ {
				if v, m, err := d.http.Inspect(payload[i:]); v != VerdictUnknown {
					if v == VerdictMatched {
						m.PaddingOffset = i
					}
					return v, m, err
				}
			}
		}
	}

	return VerdictUnknown, Metadata{}, nil
}
