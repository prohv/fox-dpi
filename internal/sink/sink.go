package sink

import "sync/atomic"

// Sink abstracts asynchronous event consumption for flows and security alerts.
type Sink interface {
	EmitFlow(event FlowEvent)
	EmitAlert(event AlertEvent)
	Stats() Stats
	Close() error
}

// Stats captures operational metrics from the sink.
type Stats struct {
	EmittedFlows  uint64
	EmittedAlerts uint64
	DroppedFlows  uint64
	DroppedAlerts uint64
}

// AtomicStats provides thread-safe counters for sink metrics.
type AtomicStats struct {
	EmittedFlows  uint64
	EmittedAlerts uint64
	DroppedFlows  uint64
	DroppedAlerts uint64
}

// Snapshot returns a point-in-time copy of the metrics.
func (s *AtomicStats) Snapshot() Stats {
	return Stats{
		EmittedFlows:  atomic.LoadUint64(&s.EmittedFlows),
		EmittedAlerts: atomic.LoadUint64(&s.EmittedAlerts),
		DroppedFlows:  atomic.LoadUint64(&s.DroppedFlows),
		DroppedAlerts: atomic.LoadUint64(&s.DroppedAlerts),
	}
}

// NoopSink discards all telemetry (useful for benchmarking or headless mode).
type NoopSink struct {
	stats AtomicStats
}

// NewNoopSink constructs a discarding sink.
func NewNoopSink() *NoopSink {
	return &NoopSink{}
}

func (n *NoopSink) EmitFlow(event FlowEvent) {
	atomic.AddUint64(&n.stats.EmittedFlows, 1)
}

func (n *NoopSink) EmitAlert(event AlertEvent) {
	atomic.AddUint64(&n.stats.EmittedAlerts, 1)
}

func (n *NoopSink) Stats() Stats {
	return n.stats.Snapshot()
}

func (n *NoopSink) Close() error {
	return nil
}
