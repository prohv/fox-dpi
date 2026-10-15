package sink

import (
	"strconv"
	"time"
)

// FlowEvent represents telemetry exported when a flow terminates or expires.
type FlowEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	SrcIP       string            `json:"src_ip"`
	DstIP       string            `json:"dst_ip"`
	SrcPort     uint16            `json:"src_port"`
	DstPort     uint16            `json:"dst_port"`
	Protocol    string            `json:"protocol"`
	L7Protocol  string            `json:"l7_protocol,omitempty"`
	Host        string            `json:"host,omitempty"`
	Packets     uint64            `json:"packets"`
	Bytes       uint64            `json:"bytes"`
	DurationMs  int64             `json:"duration_ms"`
	HandshakeMs int64             `json:"handshake_ms,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
}

// AlertEvent represents a security notification emitted upon anomalous traffic.
type AlertEvent struct {
	Timestamp time.Time         `json:"timestamp"`
	Rule      string            `json:"rule"`
	Severity  string            `json:"severity"`
	SrcIP     string            `json:"src_ip"`
	DstIP     string            `json:"dst_ip"`
	SrcPort   uint16            `json:"src_port"`
	DstPort   uint16            `json:"dst_port"`
	Protocol  string            `json:"protocol"`
	Message   string            `json:"message"`
	Details   map[string]string `json:"details,omitempty"`
}

const hexDigits = "0123456789abcdef"

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			} else {
				dst = append(dst, c)
			}
		}
	}
	dst = append(dst, '"')
	return dst
}

// AppendJSON serializes the FlowEvent to valid JSON directly without reflection or heap allocations.
func (e *FlowEvent) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"timestamp":`...)
	dst = append(dst, '"')
	dst = e.Timestamp.AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, `","src_ip":`...)
	dst = appendJSONString(dst, e.SrcIP)
	dst = append(dst, `,"dst_ip":`...)
	dst = appendJSONString(dst, e.DstIP)
	dst = append(dst, `,"src_port":`...)
	dst = strconv.AppendUint(dst, uint64(e.SrcPort), 10)
	dst = append(dst, `,"dst_port":`...)
	dst = strconv.AppendUint(dst, uint64(e.DstPort), 10)
	dst = append(dst, `,"protocol":`...)
	dst = appendJSONString(dst, e.Protocol)

	if e.L7Protocol != "" {
		dst = append(dst, `,"l7_protocol":`...)
		dst = appendJSONString(dst, e.L7Protocol)
	}
	if e.Host != "" {
		dst = append(dst, `,"host":`...)
		dst = appendJSONString(dst, e.Host)
	}

	dst = append(dst, `,"packets":`...)
	dst = strconv.AppendUint(dst, e.Packets, 10)
	dst = append(dst, `,"bytes":`...)
	dst = strconv.AppendUint(dst, e.Bytes, 10)
	dst = append(dst, `,"duration_ms":`...)
	dst = strconv.AppendInt(dst, e.DurationMs, 10)

	if e.HandshakeMs > 0 {
		dst = append(dst, `,"handshake_ms":`...)
		dst = strconv.AppendInt(dst, e.HandshakeMs, 10)
	}

	if len(e.Details) > 0 {
		dst = append(dst, `,"details":{`...)
		first := true
		for k, v := range e.Details {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = appendJSONString(dst, k)
			dst = append(dst, ':')
			dst = appendJSONString(dst, v)
		}
		dst = append(dst, '}')
	}

	dst = append(dst, '}')
	return dst
}

// AppendJSON serializes the AlertEvent to valid JSON directly without reflection or heap allocations.
func (e *AlertEvent) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"timestamp":`...)
	dst = append(dst, '"')
	dst = e.Timestamp.AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, `","rule":`...)
	dst = appendJSONString(dst, e.Rule)
	dst = append(dst, `,"severity":`...)
	dst = appendJSONString(dst, e.Severity)
	dst = append(dst, `,"src_ip":`...)
	dst = appendJSONString(dst, e.SrcIP)
	dst = append(dst, `,"dst_ip":`...)
	dst = appendJSONString(dst, e.DstIP)
	dst = append(dst, `,"src_port":`...)
	dst = strconv.AppendUint(dst, uint64(e.SrcPort), 10)
	dst = append(dst, `,"dst_port":`...)
	dst = strconv.AppendUint(dst, uint64(e.DstPort), 10)
	dst = append(dst, `,"protocol":`...)
	dst = appendJSONString(dst, e.Protocol)
	dst = append(dst, `,"message":`...)
	dst = appendJSONString(dst, e.Message)

	if len(e.Details) > 0 {
		dst = append(dst, `,"details":{`...)
		first := true
		for k, v := range e.Details {
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = appendJSONString(dst, k)
			dst = append(dst, ':')
			dst = appendJSONString(dst, v)
		}
		dst = append(dst, '}')
	}

	dst = append(dst, '}')
	return dst
}
