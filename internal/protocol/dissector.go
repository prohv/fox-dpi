package protocol

import "errors"

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
type Metadata struct {
	Protocol string
	Host     string
	Details  map[string]string
}

// Dissector defines the contract for protocol parsers operating over raw byte slices.
type Dissector interface {
	Name() string
	Inspect(payload []byte) (Verdict, Metadata, error)
}
