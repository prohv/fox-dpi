package flow

import (
	"net/netip"
	"sync"
	"time"

	"fox-dpi/internal/reassembly"
)

// NumShards must be a power of 2 for fast bitwise masking.
const NumShards = 64

type FlowShard struct {
	mu    sync.RWMutex
	flows map[FlowKey]*Flow
}

// FlowTable manages active flows across 64 concurrent shards.
type FlowTable struct {
	shards [NumShards]FlowShard
}

// NewFlowTable initializes pre-allocated shard maps.
func NewFlowTable() *FlowTable {
	table := &FlowTable{}
	for i := 0; i < NumShards; i++ {
		table.shards[i].flows = make(map[FlowKey]*Flow, 1024)
	}
	return table
}

func (t *FlowTable) shardIndex(key FlowKey) int {
	return int(key.Hash() & (NumShards - 1))
}

// GetOrCreate finds the existing flow or initializes a new record with the packet's endpoints.
func (t *FlowTable) GetOrCreate(key FlowKey, srcIP netip.Addr, srcPort uint16, length int, tcpFlags uint8, ts time.Time) *Flow {
	idx := t.shardIndex(key)
	shard := &t.shards[idx]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	flow, exists := shard.flows[key]
	if !exists {
		flow = NewFlow(key, srcIP, srcPort, length, tcpFlags, ts)
		shard.flows[key] = flow
		return flow
	}

	flow.Update(srcIP, srcPort, length, tcpFlags, ts)
	return flow
}

// Get looks up a flow under read lock.
func (t *FlowTable) Get(key FlowKey) (*Flow, bool) {
	idx := t.shardIndex(key)
	shard := &t.shards[idx]

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	flow, exists := shard.flows[key]
	return flow, exists
}

// Count returns the aggregate number of active flows across all shards.
func (t *FlowTable) Count() int {
	total := 0
	for i := 0; i < NumShards; i++ {
		t.shards[i].mu.RLock()
		total += len(t.shards[i].flows)
		t.shards[i].mu.RUnlock()
	}
	return total
}

// EvictExpired sweeps through shards, removing flows exceeding their retention deadline.
func (t *FlowTable) EvictExpired(now time.Time, tcpIdle, udpIdle, closeGrace time.Duration) int {
	return t.EvictExpiredWithCallback(now, tcpIdle, udpIdle, closeGrace, nil)
}

// EvictExpiredWithCallback sweeps through shards, purges expired flows, recycles buffers, and invokes onEvict.
func (t *FlowTable) EvictExpiredWithCallback(now time.Time, tcpIdle, udpIdle, closeGrace time.Duration, onEvict func(*Flow)) int {
	evicted := 0
	for i := 0; i < NumShards; i++ {
		shard := &t.shards[i]

		shard.mu.Lock()
		for key, f := range shard.flows {
			if f.IsExpired(now, tcpIdle, udpIdle, closeGrace) {
				delete(shard.flows, key)
				if f.Reassembler != nil {
					reassembly.PutReassembler(f.Reassembler)
					f.Reassembler = nil
				}
				if onEvict != nil {
					onEvict(f)
				}
				evicted++
			}
		}
		shard.mu.Unlock()
	}
	return evicted
}

// DrainAll removes and emits all active flows across all shards upon engine shutdown.
func (t *FlowTable) DrainAll(onEvict func(*Flow)) int {
	drained := 0
	for i := 0; i < NumShards; i++ {
		shard := &t.shards[i]

		shard.mu.Lock()
		for key, f := range shard.flows {
			delete(shard.flows, key)
			if f.Reassembler != nil {
				reassembly.PutReassembler(f.Reassembler)
				f.Reassembler = nil
			}
			if onEvict != nil {
				onEvict(f)
			}
			drained++
		}
		shard.mu.Unlock()
	}
	return drained
}

