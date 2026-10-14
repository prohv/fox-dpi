package protocol

import (
	"bytes"
	"strings"
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
			matchedMethod = strings.TrimSpace(string(m))
			break
		}
	}

	if matchedMethod == "" {
		return VerdictUnknown, Metadata{}, nil
	}

	// 2. Check for end of headers (\r\n\r\n or \n\n)
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	delimiterLen := 4
	if headerEnd == -1 {
		headerEnd = bytes.Index(payload, []byte("\n\n"))
		delimiterLen = 2
	}

	if headerEnd == -1 {
		// Method matched, but headers are incomplete across segments
		return VerdictNeedMoreData, Metadata{}, nil
	}

	headerSection := payload[:headerEnd+delimiterLen]
	lines := bytes.Split(headerSection, []byte("\n"))

	var host, userAgent, path string

	// Parse request target from line 0
	if len(lines) > 0 {
		reqParts := bytes.Fields(lines[0])
		if len(reqParts) >= 2 {
			path = string(reqParts[1])
		}
	}

	for _, line := range lines[1:] {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}

		headerName := strings.ToLower(string(bytes.TrimSpace(line[:colonIdx])))
		headerVal := string(bytes.TrimSpace(line[colonIdx+1:]))

		switch headerName {
		case "host":
			// Strip port if present: example.com:8080 -> example.com
			if h, _, found := strings.Cut(headerVal, ":"); found {
				host = h
			} else {
				host = headerVal
			}
		case "user-agent":
			userAgent = headerVal
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
