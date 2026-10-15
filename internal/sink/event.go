package sink

import "time"

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
