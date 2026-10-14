package protocol

import (
	"bytes"
)

// HTTPDissector parses HTTP/1.1 request lines and headers without decoding full bodies.
type HTTPDissector struct{}

func NewHTTPDissector() *HTTPDissector {
	return &HTTPDissector{}
}

func (d *HTTPDissector) Name() string {
	return "HTTP"
}

// Known HTTP request method prefixes
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
}

// Inspect identifies ASCII HTTP methods, checks header boundaries, and extracts Host and User-Agent.
func (d *HTTPDissector) Inspect(payload []byte) (Verdict, Metadata, error) {
	if len(payload) < 4 {
		return VerdictUnknown, Metadata{}, nil
	}

	// 1. Fast match request method
	var matchedMethod string
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, m) {
			matchedMethod = string(bytes.TrimSpace(m))
			break
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
	var host, userAgent, path string

	// Parse request target from line 0
	firstLineEnd := bytes.IndexByte(headerSection, '\n')
	if firstLineEnd == -1 {
		firstLineEnd = len(headerSection)
	}
	firstLine := bytes.TrimRight(headerSection[:firstLineEnd], "\r")
	if sp1 := bytes.IndexByte(firstLine, ' '); sp1 != -1 {
		rest := firstLine[sp1+1:]
		if sp2 := bytes.IndexByte(rest, ' '); sp2 != -1 {
			path = string(rest[:sp2])
		} else {
			path = string(rest)
		}
	}

	// Scan headers line-by-line without heap allocations
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
		line = bytes.TrimRight(line, "\r")
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}

		key := bytes.TrimSpace(line[:colonIdx])
		val := bytes.TrimSpace(line[colonIdx+1:])

		if bytes.EqualFold(key, []byte("host")) {
			if h, _, found := bytes.Cut(val, []byte(":")); found {
				host = string(h)
			} else {
				host = string(val)
			}
		} else if bytes.EqualFold(key, []byte("user-agent")) {
			userAgent = string(val)
		}
	}

	if host == "" {
		host = "unknown"
	}

	return VerdictMatched, Metadata{
		Protocol: "HTTP",
		Host:     host,
		Details: map[string]string{
			"method":     matchedMethod,
			"path":       path,
			"user_agent": userAgent,
		},
	}, nil
}
