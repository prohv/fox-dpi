package engine

import (
	"context"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/flow"

	"github.com/google/gopacket/layers"
)

// Metrics exposes real-time aggregate packet and flow counters.
type Metrics struct {
	TotalPackets uint64
	TotalBytes   uint64
	DropPackets  uint64
	ActiveFlows  int
	EvictedFlows uint64
}

// Engine orchestrates zero-alloc packet decapsulation and flow table state.
type Engine struct {
	table        *flow.FlowTable
	decapsulator *capture.Decapsulator
	worker       *flow.EvictionWorker
	evictConfig  flow.EvictionConfig

	totalPackets uint64
	totalBytes   uint64
	dropPackets  uint64
}

// NewEngine initializes an engine configured for the provided link layer.
func NewEngine(linkType layers.LinkType, cfg flow.EvictionConfig) (*Engine, error) {
	d, err := capture.NewDecapsulator(linkType)
	if err != nil {
		return nil, fmt.Errorf("init decapsulator: %w", err)
	}

	tbl := flow.NewFlowTable()
	worker := flow.NewEvictionWorker(tbl, cfg)

	return &Engine{
		table:        tbl,
		decapsulator: d,
		worker:       worker,
		evictConfig:  cfg,
	}, nil
}

// Table returns the underlying flow table.
func (e *Engine) Table() *flow.FlowTable {
	return e.table
}

// ProcessFrame decapsulates a single raw frame and updates its canonical flow.
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
	return f, nil
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

// Metrics returns a snapshot of current engine stats.
func (e *Engine) Metrics() Metrics {
	return Metrics{
		TotalPackets: atomic.LoadUint64(&e.totalPackets),
		TotalBytes:   atomic.LoadUint64(&e.totalBytes),
		DropPackets:  atomic.LoadUint64(&e.dropPackets),
		ActiveFlows:  e.table.Count(),
		EvictedFlows: e.worker.TotalEvicted(),
	}
}
