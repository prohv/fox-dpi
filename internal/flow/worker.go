package flow

import (
	"context"
	"sync/atomic"
	"time"
)

// EvictionConfig controls retention deadlines and sweep frequency.
type EvictionConfig struct {
	SweepInterval time.Duration
	TCPIdle       time.Duration
	UDPIdle       time.Duration
	CloseGrace    time.Duration
}

// DefaultEvictionConfig returns the production baseline parameters.
func DefaultEvictionConfig() EvictionConfig {
	return EvictionConfig{
		SweepInterval: 5 * time.Second,
		TCPIdle:       30 * time.Second,
		UDPIdle:       5 * time.Second,
		CloseGrace:    2 * time.Second,
	}
}

// EvictionWorker runs periodic background sweeps across all shards.
type EvictionWorker struct {
	table        *FlowTable
	config       EvictionConfig
	onEvict      func(*Flow)
	totalEvicted uint64
	sweepCount   uint64
}

// NewEvictionWorker creates a worker bound to a flow table.
func NewEvictionWorker(table *FlowTable, cfg EvictionConfig, onEvict ...func(*Flow)) *EvictionWorker {
	var cb func(*Flow)
	if len(onEvict) > 0 {
		cb = onEvict[0]
	}
	return &EvictionWorker{
		table:   table,
		config:  cfg,
		onEvict: cb,
	}
}

// Start spawns the background eviction loop until the context is canceled.
func (w *EvictionWorker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.config.SweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			evicted := w.table.EvictExpiredWithCallback(t, w.config.TCPIdle, w.config.UDPIdle, w.config.CloseGrace, w.onEvict)
			atomic.AddUint64(&w.totalEvicted, uint64(evicted))
			atomic.AddUint64(&w.sweepCount, 1)
		}
	}
}

// TotalEvicted returns the cumulative number of flows purged from memory.
func (w *EvictionWorker) TotalEvicted() uint64 {
	return atomic.LoadUint64(&w.totalEvicted)
}
