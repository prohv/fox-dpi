package engine

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/flow"
	"fox-dpi/internal/protocol"
	"fox-dpi/internal/reassembly"
	"fox-dpi/internal/sink"

	"github.com/google/gopacket/layers"
)

// Metrics exposes real-time aggregate packet and flow counters.
type Metrics struct {
	TotalPackets  uint64
	TotalBytes    uint64
	DropPackets   uint64
	ActiveFlows   int
	EvictedFlows  uint64
	EmittedFlows  uint64
	EmittedAlerts uint64
	DroppedFlows  uint64
	DroppedAlerts uint64
}

// Engine orchestrates zero-alloc packet decapsulation and flow table state.
type Engine struct {
	table        *flow.FlowTable
	decapsulator *capture.Decapsulator
	dispatcher   *protocol.Dispatcher
	worker       *flow.EvictionWorker
	evictConfig  flow.EvictionConfig
	sink         sink.Sink

	totalPackets uint64
	totalBytes   uint64
	dropPackets  uint64
}

// NewEngine initializes an engine configured for the provided link layer.
func NewEngine(linkType layers.LinkType, cfg flow.EvictionConfig, sinks ...sink.Sink) (*Engine, error) {
	d, err := capture.NewDecapsulator(linkType)
	if err != nil {
		return nil, fmt.Errorf("init decapsulator: %w", err)
	}

	var s sink.Sink = sink.NewNoopSink()
	if len(sinks) > 0 && sinks[0] != nil {
		s = sinks[0]
	}

	tbl := flow.NewFlowTable()
	eng := &Engine{
		table:        tbl,
		decapsulator: d,
		dispatcher:   protocol.NewDispatcher(),
		evictConfig:  cfg,
		sink:         s,
	}

	worker := flow.NewEvictionWorker(tbl, cfg, eng.emitFlowEvent)
	eng.worker = worker

	return eng, nil
}

// Table returns the underlying flow table.
func (e *Engine) Table() *flow.FlowTable {
	return e.table
}

// ProcessFrame decapsulates a single raw frame, reassembles streams, and updates L7 metadata.
func (e *Engine) ProcessFrame(data []byte, ts time.Time) (*flow.Flow, error) {
	atomic.AddUint64(&e.totalPackets, 1)
	atomic.AddUint64(&e.totalBytes, uint64(len(data)))

	pkt, err := e.decapsulator.Decode(data)
	if err != nil {
		atomic.AddUint64(&e.dropPackets, 1)
		return nil, err
	}

	key := flow.NewFlowKey(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, pkt.Proto)
	f := e.table.GetOrCreate(key, pkt.SrcIP, pkt.SrcPort, pkt.Length, pkt.TCPFlags, ts)

	// L7 Inspection Pipeline
	if len(pkt.Payload) > 0 && !f.L7Bypass {
		if pkt.Proto == 17 { // UDP (e.g. DNS)
			verdict, meta, _ := e.dispatcher.Dispatch(pkt.Payload, 17)
			if verdict == protocol.VerdictMatched {
				f.SetL7Metadata(meta)
				e.checkSecurityAlerts(f)
			}
		} else if pkt.Proto == 6 { // TCP (e.g. TLS, HTTP)
			if f.Reassembler == nil {
				f.Reassembler = reassembly.GetReassembler(pkt.TCPSeq)
			}
			stream := f.Reassembler.Push(pkt.TCPSeq, pkt.Payload)
			if len(stream) > 0 {
				verdict, meta, _ := e.dispatcher.Dispatch(stream, 6)
				if verdict == protocol.VerdictMatched {
					f.SetL7Metadata(meta)
					e.checkSecurityAlerts(f)
				} else if verdict == protocol.VerdictUnknown && len(stream) >= 512 {
					// Stop inspecting unknown binary protocols after 512 bytes
					f.L7Bypass = true
					reassembly.PutReassembler(f.Reassembler)
					f.Reassembler = nil
				}
			}
		}
	}

	return f, nil
}

func (e *Engine) checkSecurityAlerts(f *flow.Flow) {
	if f.AlertEmitted || !f.L7Identified || e.sink == nil {
		return
	}

	respIP := f.ResponderIP()
	respPort := f.ResponderPort()
	protoStr := "TCP"
	if f.Key.Proto == 17 {
		protoStr = "UDP"
	}

	// Rule 0: Protocol Padding Evasion (Junk noise prepended before L7 payload)
	if padOffset, ok := f.L7Metadata.Details["padding_offset"]; ok && padOffset != "0" {
		f.AlertEmitted = true
		e.sink.EmitAlert(sink.AlertEvent{
			Timestamp: f.LastSeen,
			Rule:      "PROTOCOL_PADDING_EVASION",
			Severity:  "HIGH",
			SrcIP:     f.InitiatorIP.String(),
			DstIP:     respIP.String(),
			SrcPort:   f.InitiatorPort,
			DstPort:   respPort,
			Protocol:  protoStr,
			Message:   fmt.Sprintf("Protocol padding detected: %s junk bytes prepended before %s payload", padOffset, f.L7Metadata.Protocol),
			Details:   f.L7Metadata.Details,
		})
		return
	}

	// Rule 1: HTTP on port 443 (Cleartext on TLS port)
	if f.L7Metadata.Protocol == "HTTP" && respPort == 443 {
		f.AlertEmitted = true
		e.sink.EmitAlert(sink.AlertEvent{
			Timestamp: f.LastSeen,
			Rule:      "PORT_SPOOF_HTTP",
			Severity:  "HIGH",
			SrcIP:     f.InitiatorIP.String(),
			DstIP:     respIP.String(),
			SrcPort:   f.InitiatorPort,
			DstPort:   respPort,
			Protocol:  protoStr,
			Message:   "Cleartext HTTP traffic detected on HTTPS port 443",
			Details:   f.L7Metadata.Details,
		})
		return
	}

	// Rule 2: TLS Port Checks
	if f.L7Metadata.Protocol == "TLS" {
		// Fast-path: standard HTTPS port (99% of traffic), exit immediately in 1 cycle
		if respPort == 443 || respPort == 8443 {
			return
		}

		f.AlertEmitted = true
		if respPort == 80 || respPort == 8080 {
			// Plain HTTP port spoofing
			e.sink.EmitAlert(sink.AlertEvent{
				Timestamp: f.LastSeen,
				Rule:      "PORT_SPOOF_TLS",
				Severity:  "WARN",
				SrcIP:     f.InitiatorIP.String(),
				DstIP:     respIP.String(),
				SrcPort:   f.InitiatorPort,
				DstPort:   respPort,
				Protocol:  protoStr,
				Message:   fmt.Sprintf("Encrypted TLS traffic detected on plain HTTP port %d", respPort),
				Details:   f.L7Metadata.Details,
			})
			return
		}

		// TLS on arbitrary non-standard port (e.g. 4444, 1337 - C2 beaconing)
		e.sink.EmitAlert(sink.AlertEvent{
			Timestamp: f.LastSeen,
			Rule:      "SUSPICIOUS_HIGH_PORT_TLS",
			Severity:  "HIGH",
			SrcIP:     f.InitiatorIP.String(),
			DstIP:     respIP.String(),
			SrcPort:   f.InitiatorPort,
			DstPort:   respPort,
			Protocol:  protoStr,
			Message:   fmt.Sprintf("Encrypted TLS traffic detected on non-standard port %d", respPort),
			Details:   f.L7Metadata.Details,
		})
		return
	}

	// Rule 3: DNS on non-standard port (not 53 and not 853)
	if f.L7Metadata.Protocol == "DNS" && respPort != 53 && respPort != 853 {
		f.AlertEmitted = true
		e.sink.EmitAlert(sink.AlertEvent{
			Timestamp: f.LastSeen,
			Rule:      "ANOMALOUS_DNS_PORT",
			Severity:  "INFO",
			SrcIP:     f.InitiatorIP.String(),
			DstIP:     respIP.String(),
			SrcPort:   f.InitiatorPort,
			DstPort:   respPort,
			Protocol:  protoStr,
			Message:   fmt.Sprintf("DNS traffic detected on non-standard port %d", respPort),
			Details:   f.L7Metadata.Details,
		})
		return
	}
}

func (e *Engine) emitFlowEvent(f *flow.Flow) {
	if e.sink == nil {
		return
	}

	protoStr := "OTHER"
	if f.Key.Proto == 6 {
		protoStr = "TCP"
	} else if f.Key.Proto == 17 {
		protoStr = "UDP"
	}

	event := sink.FlowEvent{
		Timestamp:   f.LastSeen,
		SrcIP:       f.InitiatorIP.String(),
		DstIP:       f.ResponderIP().String(),
		SrcPort:     f.InitiatorPort,
		DstPort:     f.ResponderPort(),
		Protocol:    protoStr,
		L7Protocol:  f.L7Metadata.Protocol,
		Host:        f.L7Metadata.Host,
		Packets:     f.ClientPackets + f.ServerPackets,
		Bytes:       f.ClientBytes + f.ServerBytes,
		DurationMs:  f.LastSeen.Sub(f.FirstSeen).Milliseconds(),
		HandshakeMs: f.HandshakeRTT.Milliseconds(),
		Details:     f.L7Metadata.Details,
	}
	e.sink.EmitFlow(event)
}

// Run ingests packets sequentially from a source until EOF or context cancellation.
func (e *Engine) Run(ctx context.Context, src capture.PacketSource) error {
	evictCtx, cancelEvict := context.WithCancel(ctx)
	defer cancelEvict()

	go e.worker.Start(evictCtx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, ci, err := src.ReadPacket()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read packet: %w", err)
		}

		ts := ci.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}

		_, _ = e.ProcessFrame(data, ts)
	}
}

// Close drains active flows, emits them to the sink, and shuts down the sink.
func (e *Engine) Close() error {
	e.table.DrainAll(e.emitFlowEvent)
	if e.sink != nil {
		return e.sink.Close()
	}
	return nil
}

// Metrics returns a snapshot of current engine stats.
func (e *Engine) Metrics() Metrics {
	sinkStats := e.sink.Stats()
	return Metrics{
		TotalPackets:  atomic.LoadUint64(&e.totalPackets),
		TotalBytes:    atomic.LoadUint64(&e.totalBytes),
		DropPackets:   atomic.LoadUint64(&e.dropPackets),
		ActiveFlows:   e.table.Count(),
		EvictedFlows:  e.worker.TotalEvicted(),
		EmittedFlows:  sinkStats.EmittedFlows,
		EmittedAlerts: sinkStats.EmittedAlerts,
		DroppedFlows:  sinkStats.DroppedFlows,
		DroppedAlerts: sinkStats.DroppedAlerts,
	}
}

