package protocol

import (
	"bytes"
	"encoding/binary"
)

// HTTPDissector parses HTTP/1.1 request lines and headers without decoding full bodies.
type HTTPDissector struct{}

func NewHTTPDissector() *HTTPDissector {
	return &HTTPDissector{}
}

func (d *HTTPDissector) Name() string {
	return "HTTP"
}

// 32-bit little-endian constants for instant 1-cycle method dispatch
const (
	methodGET  = 0x20544547 // "GET "
	methodPOST = 0x54534F50 // "POST"
	methodHEAD = 0x44414548 // "HEAD"
	methodPUT  = 0x20545550 // "PUT "

	// "HOST" in 32-bit little-endian
	magicHost = uint32('H') | uint32('O')<<8 | uint32('S')<<16 | uint32('T')<<24
	// "USER" in 32-bit little-endian
	magicUser = uint32('U') | uint32('S')<<8 | uint32('E')<<16 | uint32('R')<<24
)

func trimHTTPSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// Inspect identifies ASCII HTTP methods, checks header boundaries, and extracts Host and User-Agent.
func (d *HTTPDissector) Inspect(payload []byte) (Verdict, Metadata, error) {
	if len(payload) < 4 {
		return VerdictUnknown, Metadata{}, nil
	}

	// 1. Single-instruction 32-bit method matching
	magic := binary.LittleEndian.Uint32(payload[:4])
	var matchedMethod string
	switch magic {
	case methodGET:
		matchedMethod = "GET"
	case methodPOST:
		if len(payload) > 4 && payload[4] == ' ' {
			matchedMethod = "POST"
		}
	case methodHEAD:
		if len(payload) > 4 && payload[4] == ' ' {
			matchedMethod = "HEAD"
		}
	case methodPUT:
		matchedMethod = "PUT"
	default:
		// Fallback for rarer methods
		if bytes.HasPrefix(payload, []byte("DELETE ")) {
			matchedMethod = "DELETE"
		} else if bytes.HasPrefix(payload, []byte("OPTIONS ")) {
			matchedMethod = "OPTIONS"
		} else if bytes.HasPrefix(payload, []byte("PATCH ")) {
			matchedMethod = "PATCH"
		} else if bytes.HasPrefix(payload, []byte("CONNECT ")) {
			matchedMethod = "CONNECT"
		}
	}

	if matchedMethod == "" {
		return VerdictUnknown, Metadata{}, nil
	}

	// 2. Check for end of headers (\r\n\r\n or \n\n)
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(payload, []byte("\n\n"))
	}

	if headerEnd == -1 {
		// Method matched, but headers are incomplete across segments
		return VerdictNeedMoreData, Metadata{}, nil
	}

	headerSection := payload[:headerEnd]
	var host, userAgent, path, duplicateHost string

	// Parse request target from line 0
	firstLineEnd := bytes.IndexByte(headerSection, '\n')
	if firstLineEnd == -1 {
		firstLineEnd = len(headerSection)
	}
	firstLine := headerSection[:firstLineEnd]
	if len(firstLine) > 0 && firstLine[len(firstLine)-1] == '\r' {
		firstLine = firstLine[:len(firstLine)-1]
	}

	if sp1 := bytes.IndexByte(firstLine, ' '); sp1 != -1 {
		rest := firstLine[sp1+1:]
		if sp2 := bytes.IndexByte(rest, ' '); sp2 != -1 {
			path = InternString(rest[:sp2])
		} else {
			path = InternString(rest)
		}
	}

	// Fast line-by-line header parsing
	rem := headerSection[firstLineEnd:]
	for len(rem) > 0 {
		if rem[0] == '\n' {
			rem = rem[1:]
			continue
		}
		lineEnd := bytes.IndexByte(rem, '\n')
		var line []byte
		if lineEnd == -1 {
			line = rem
			rem = nil
		} else {
			line = rem[:lineEnd]
			rem = rem[lineEnd+1:]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}

		key := trimHTTPSpace(line[:colonIdx])
		val := trimHTTPSpace(line[colonIdx+1:])

		// Bitwise case-insensitive header matching
		if len(key) == 4 && (binary.LittleEndian.Uint32(key)&0xDFDFDFDF) == magicHost {
			var parsedHost string
			if len(val) > 0 && val[0] == '[' {
				// RFC 3986 bracketed IPv6 address literal
				if closeIdx := bytes.IndexByte(val, ']'); closeIdx != -1 {
					parsedHost = InternString(val[:closeIdx+1])
				} else {
					parsedHost = InternString(val)
				}
			} else if colon := bytes.IndexByte(val, ':'); colon != -1 {
				parsedHost = InternString(val[:colon])
			} else {
				parsedHost = InternString(val)
			}

			if host == "" {
				host = parsedHost
			} else if duplicateHost == "" {
				// RFC 7230 Section 5.4 violation: duplicate Host header detected
				duplicateHost = parsedHost
			}
		} else if len(key) == 10 && (binary.LittleEndian.Uint32(key[:4])&0xDFDFDFDF) == magicUser && key[4] == '-' {
			userAgent = InternString(val)
		}
	}

	if host == "" {
		host = "unknown"
	}

	return VerdictMatched, Metadata{
		Protocol:      "HTTP",
		Host:          host,
		Method:        matchedMethod,
		Path:          path,
		UserAgent:     userAgent,
		DuplicateHost: duplicateHost,
	}, nil
}
