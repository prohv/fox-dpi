package protocol

import (
	"errors"
	"strconv"
)

// Verdict indicates whether a dissector recognized, matched, or needs more stream data.
type Verdict uint8

const (
	VerdictUnknown Verdict = iota
	VerdictNeedMoreData
	VerdictMatched
)

var (
	ErrPayloadTooShort = errors.New("payload shorter than minimum protocol header")
	ErrMalformedData   = errors.New("payload structure does not conform to protocol specification")
)

// Metadata contains unencrypted Layer 7 identifiers extracted from packet payloads.
// Standard attributes are stored in typed fields to achieve 100% zero-allocation inspection.
type Metadata struct {
	Protocol      string
	Host          string
	Method        string
	Path          string
	UserAgent     string
	SNI           string
	Version       string
	QType         string
	Role          string
	DuplicateHost string
	PaddingOffset int
	Details       map[string]string
}

// Detail retrieves a metadata property without allocating a map.
func (m Metadata) Detail(key string) string {
	switch key {
	case "method":
		return m.Method
	case "path":
		return m.Path
	case "user_agent":
		return m.UserAgent
	case "sni":
		return m.SNI
	case "version":
		return m.Version
	case "qtype":
		return m.QType
	case "role":
		return m.Role
	case "duplicate_host":
		return m.DuplicateHost
	case "padding_offset":
		if m.PaddingOffset > 0 {
			return strconv.Itoa(m.PaddingOffset)
		}
	}
	if m.Details != nil {
		return m.Details[key]
	}
	return ""
}

// DetailsMap constructs a map representation for asynchronous sink telemetry.
func (m Metadata) DetailsMap() map[string]string {
	if m.Details != nil {
		return m.Details
	}
	d := make(map[string]string)
	if m.Method != "" {
		d["method"] = m.Method
	}
	if m.Path != "" {
		d["path"] = m.Path
	}
	if m.UserAgent != "" {
		d["user_agent"] = m.UserAgent
	}
	if m.SNI != "" {
		d["sni"] = m.SNI
	}
	if m.Version != "" {
		d["version"] = m.Version
	}
	if m.QType != "" {
		d["qtype"] = m.QType
	}
	if m.Role != "" {
		d["role"] = m.Role
	}
	if m.DuplicateHost != "" {
		d["duplicate_host"] = m.DuplicateHost
	}
	if m.PaddingOffset > 0 {
		d["padding_offset"] = strconv.Itoa(m.PaddingOffset)
	}
	return d
}

// Dissector defines the contract for protocol parsers operating over raw byte slices.
type Dissector interface {
	Name() string
	Inspect(payload []byte) (Verdict, Metadata, error)
}
