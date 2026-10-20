package flow

import (
	"net/netip"
	"time"

	"fox-dpi/internal/protocol"
	"fox-dpi/internal/reassembly"
)

// Direction indicates the transmission direction relative to the connection initiator.
type Direction uint8

const (
	DirectionClientToServer Direction = iota
	DirectionServerToClient
)

// TCP flag bitmasks for stateful connection tracking
const (
	flagSYN uint8 = 1 << 0
	flagACK uint8 = 1 << 1
	flagFIN uint8 = 1 << 2
	flagRST uint8 = 1 << 3
)

// Flow maintains connection metrics and lifecycle state for a bidirectional conversation.
type Flow struct {
	Key           FlowKey
	InitiatorIP   netip.Addr
	InitiatorPort uint16

	ClientPackets uint64
	ClientBytes   uint64
	ServerPackets uint64
	ServerBytes   uint64

	FirstSeen time.Time
	LastSeen  time.Time
	CloseTime time.Time

	Closing      bool
	SynSeen      bool
	SynAckSeen   bool
	HandshakeRTT time.Duration

	L7Metadata   protocol.Metadata
	L7Identified bool
	L7Bypass     bool
	AlertEmitted bool
	Reassembler  *reassembly.StreamReassembler
}

// NewFlow initializes a new connection record with the initiator set from the first packet.
func NewFlow(key FlowKey, srcIP netip.Addr, srcPort uint16, length int, tcpFlags uint8, t time.Time) *Flow {
	f := &Flow{
		Key:           key,
		InitiatorIP:   srcIP,
		InitiatorPort: srcPort,
		FirstSeen:     t,
		LastSeen:      t,
	}
	f.Update(srcIP, srcPort, length, tcpFlags, t)
	return f
}

// Update records directional packet volume, tracks TCP handshake latency, and detects teardown flags.
func (f *Flow) Update(srcIP netip.Addr, srcPort uint16, length int, tcpFlags uint8, t time.Time) {
	// Monotonic bounds envelope: guarantees FirstSeen <= LastSeen under packet capture clock skew
	if t.Before(f.FirstSeen) {
		f.FirstSeen = t
	}
	if t.After(f.LastSeen) {
		f.LastSeen = t
	}

	isClient := (srcIP == f.InitiatorIP && srcPort == f.InitiatorPort)
	if isClient {
		f.ClientPackets++
		f.ClientBytes += uint64(length)
	} else {
		f.ServerPackets++
		f.ServerBytes += uint64(length)
	}

	// TCP Handshake RTT tracking: SYN from client, SYN-ACK from server
	if (tcpFlags & flagSYN) != 0 {
		if isClient && (tcpFlags&flagACK) == 0 {
			f.SynSeen = true
		} else if !isClient && (tcpFlags&flagACK) != 0 && f.SynSeen && !f.SynAckSeen {
			f.SynAckSeen = true
			if t.After(f.FirstSeen) {
				f.HandshakeRTT = t.Sub(f.FirstSeen)
			}
		}
	}

	// Teardown detection: mark closing on FIN or RST
	if (tcpFlags&flagFIN) != 0 || (tcpFlags&flagRST) != 0 {
		if !f.Closing {
			f.Closing = true
			f.CloseTime = t
		}
	}
}

// IsExpired evaluates whether a flow should be evicted given idle and teardown deadlines.
func (f *Flow) IsExpired(now time.Time, tcpIdle, udpIdle, closeGrace time.Duration) bool {
	if f.Closing {
		return now.Sub(f.CloseTime) >= closeGrace
	}
	if f.Key.Proto == 6 { // TCP
		return now.Sub(f.LastSeen) >= tcpIdle
	}
	return now.Sub(f.LastSeen) >= udpIdle
}

// SetL7Metadata stores application layer identifiers.
// For encrypted TLS, it sets L7Bypass to true and frees the reassembly buffer.
// For HTTP/1.1, L7Bypass remains false to allow continuous inspection of keep-alive requests.
func (f *Flow) SetL7Metadata(meta protocol.Metadata) {
	f.L7Metadata = meta
	f.L7Identified = true

	if meta.Protocol == "TLS" {
		f.L7Bypass = true
		if f.Reassembler != nil {
			reassembly.PutReassembler(f.Reassembler)
			f.Reassembler = nil
		}
	} else if meta.Protocol == "HTTP" {
		if f.Reassembler != nil {
			reassembly.PutReassembler(f.Reassembler)
			f.Reassembler = reassembly.GetReassembler(0)
		}
	}
}

// ResponderIP returns the IP address of the peer receiving the connection.
func (f *Flow) ResponderIP() netip.Addr {
	if f.InitiatorIP == f.Key.LowIP {
		return f.Key.HighIP
	}
	return f.Key.LowIP
}

// ResponderPort returns the port of the peer receiving the connection.
func (f *Flow) ResponderPort() uint16 {
	if f.InitiatorIP == f.Key.LowIP && f.InitiatorPort == f.Key.LowPort {
		return f.Key.HighPort
	}
	if f.InitiatorIP == f.Key.HighIP && f.InitiatorPort == f.Key.HighPort {
		return f.Key.LowPort
	}
	if f.InitiatorPort == f.Key.LowPort {
		return f.Key.HighPort
	}
	return f.Key.LowPort
}

