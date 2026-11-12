package tui

import (
	"sync"
	"time"

	"fox-dpi/internal/sink"
)

// BridgeStats encapsulates live counters and protocol distributions for the TUI.
type BridgeStats struct {
	TotalPackets uint64
	TotalBytes   uint64
	ActiveFlows  int
	TotalAlerts  uint64
	TLSFlows     uint64
	HTTPFlows    uint64
	DNSFlows     uint64
	OtherFlows   uint64
	ThroughputHistory []float64 // MB/s over last N intervals
	TopHosts     []HostStat
}

// HostStat tracks aggregated volume per remote host.
type HostStat struct {
	Host  string
	Bytes uint64
	Flows int
}

// EventBridge is a non-blocking sink wrapper that buffers telemetry for the TUI.
type EventBridge struct {
	mu         sync.RWMutex
	underlying sink.Sink

	maxFlows   int
	flows      []sink.FlowEvent
	flowHead   int
	flowCount  int

	maxAlerts  int
	alerts     []sink.AlertEvent
	alertHead  int
	alertCount int

	// Distribution aggregations
	tlsFlows   uint64
	httpFlows  uint64
	dnsFlows   uint64
	otherFlows uint64

	hostMap    map[string]*HostStat

	// Throughput sampling
	lastSampleTime  time.Time
	lastSampleBytes uint64
	history         []float64
	maxHistory      int
}

// NewEventBridge creates a telemetry bridge with bounded circular buffers.
func NewEventBridge(underlying sink.Sink, maxFlows, maxAlerts int) *EventBridge {
	if maxFlows <= 0 {
		maxFlows = 512
	}
	if maxAlerts <= 0 {
		maxAlerts = 128
	}

	return &EventBridge{
		underlying:      underlying,
		maxFlows:        maxFlows,
		flows:           make([]sink.FlowEvent, maxFlows),
		maxAlerts:       maxAlerts,
		alerts:          make([]sink.AlertEvent, maxAlerts),
		hostMap:         make(map[string]*HostStat, 256),
		lastSampleTime:  time.Now(),
		maxHistory:      30, // 30 second rolling window
		history:         make([]float64, 0, 30),
	}
}

// EmitFlow queues flow telemetry into the circular buffer and forwards to disk sink.
func (b *EventBridge) EmitFlow(event sink.FlowEvent) {
	if b.underlying != nil {
		b.underlying.EmitFlow(event)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Store in ring buffer
	idx := (b.flowHead + b.flowCount) % b.maxFlows
	if b.flowCount < b.maxFlows {
		b.flowCount++
	} else {
		b.flowHead = (b.flowHead + 1) % b.maxFlows
	}
	b.flows[idx] = event

	// Protocol distribution
	switch event.L7Protocol {
	case "TLS":
		b.tlsFlows++
	case "HTTP":
		b.httpFlows++
	case "DNS":
		b.dnsFlows++
	default:
		b.otherFlows++
	}

	// Host aggregation
	host := event.Host
	if host != "" && host != "direct-ip" {
		stat, ok := b.hostMap[host]
		if !ok {
			stat = &HostStat{Host: host}
			b.hostMap[host] = stat
		}
		stat.Bytes += event.Bytes
		stat.Flows++
	}
}

// EmitAlert queues security alert telemetry into the circular buffer.
func (b *EventBridge) EmitAlert(event sink.AlertEvent) {
	if b.underlying != nil {
		b.underlying.EmitAlert(event)
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	idx := (b.alertHead + b.alertCount) % b.maxAlerts
	if b.alertCount < b.maxAlerts {
		b.alertCount++
	} else {
		b.alertHead = (b.alertHead + 1) % b.maxAlerts
	}
	b.alerts[idx] = event
}

// SnapshotFlows returns a copy of recently buffered flows (newest first).
func (b *EventBridge) SnapshotFlows() []sink.FlowEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]sink.FlowEvent, b.flowCount)
	for i := 0; i < b.flowCount; i++ {
		// Newest items first
		srcIdx := (b.flowHead + b.flowCount - 1 - i) % b.maxFlows
		out[i] = b.flows[srcIdx]
	}
	return out
}

// SnapshotAlerts returns a copy of recently captured security alerts (newest first).
func (b *EventBridge) SnapshotAlerts() []sink.AlertEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()

	out := make([]sink.AlertEvent, b.alertCount)
	for i := 0; i < b.alertCount; i++ {
		srcIdx := (b.alertHead + b.alertCount - 1 - i) % b.maxAlerts
		out[i] = b.alerts[srcIdx]
	}
	return out
}

// TickSample updates rolling throughput statistics (called every 1s by TUI tick).
func (b *EventBridge) TickSample(totalBytes uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastSampleTime).Seconds()
	if elapsed <= 0 {
		return
	}

	deltaBytes := float64(0)
	if totalBytes >= b.lastSampleBytes {
		deltaBytes = float64(totalBytes - b.lastSampleBytes)
	}
	mbps := (deltaBytes / elapsed) / (1024 * 1024)

	b.lastSampleTime = now
	b.lastSampleBytes = totalBytes

	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, mbps)
}

// BridgeSnapshot returns a current point-in-time snapshot of metrics.
func (b *EventBridge) BridgeSnapshot(totalPkts, totalBytes uint64, activeFlows int) BridgeStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	histCopy := make([]float64, len(b.history))
	copy(histCopy, b.history)

	// Top 5 talkers
	topHosts := make([]HostStat, 0, 5)
	for _, stat := range b.hostMap {
		if len(topHosts) < 5 {
			topHosts = append(topHosts, *stat)
		} else {
			// Find min in topHosts
			minIdx := 0
			for i := 1; i < len(topHosts); i++ {
				if topHosts[i].Bytes < topHosts[minIdx].Bytes {
					minIdx = i
				}
			}
			if stat.Bytes > topHosts[minIdx].Bytes {
				topHosts[minIdx] = *stat
			}
		}
	}

	return BridgeStats{
		TotalPackets:      totalPkts,
		TotalBytes:        totalBytes,
		ActiveFlows:       activeFlows,
		TotalAlerts:       uint64(b.alertCount),
		TLSFlows:          b.tlsFlows,
		HTTPFlows:         b.httpFlows,
		DNSFlows:          b.dnsFlows,
		OtherFlows:        b.otherFlows,
		ThroughputHistory: histCopy,
		TopHosts:          topHosts,
	}
}

// Stats from sink.Sink interface
func (b *EventBridge) StatsSink() sink.Stats {
	if b.underlying != nil {
		return b.underlying.Stats()
	}
	return sink.Stats{}
}

// Close forwards the close event to the underlying sink.
func (b *EventBridge) Close() error {
	if b.underlying != nil {
		return b.underlying.Close()
	}
	return nil
}

// Implement sink.Sink interface Stats method
func (b *EventBridge) Stats() sink.Stats {
	return b.StatsSink()
}
