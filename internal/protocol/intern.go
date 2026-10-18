package protocol

import "sync"

const internShards = 16

type internShard struct {
	mu    sync.RWMutex
	cache map[string]string
}

// StringInterner provides thread-safe, bounded string deduplication.
type StringInterner struct {
	shards [internShards]internShard
}

var globalInterner = NewStringInterner()

// NewStringInterner initializes pre-allocated shard maps.
func NewStringInterner() *StringInterner {
	si := &StringInterner{}
	for i := 0; i < internShards; i++ {
		si.shards[i].cache = make(map[string]string, 64)
	}
	return si
}

func hashBytes(b []byte) uint32 {
	h := uint32(2166136261)
	for _, c := range b {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}

// Intern returns an existing immutable string for the given byte slice without heap allocation on cache hit.
func (si *StringInterner) Intern(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	shardIdx := hashBytes(b) & (internShards - 1)
	shard := &si.shards[shardIdx]

	// Fast-path: read lock (Go compiler optimizes map[string]T lookup with []byte to zero-alloc)
	shard.mu.RLock()
	if s, ok := shard.cache[string(b)]; ok {
		shard.mu.RUnlock()
		return s
	}
	shard.mu.RUnlock()

	// Slow-path: write lock on cache miss
	shard.mu.Lock()
	defer shard.mu.Unlock()

	if s, ok := shard.cache[string(b)]; ok {
		return s
	}

	// Bounded capacity: cap each shard to 256 entries
	if len(shard.cache) >= 256 {
		for k := range shard.cache {
			delete(shard.cache, k)
			break
		}
	}

	s := string(b)
	shard.cache[s] = s
	return s
}

// InternString deduplicates a byte slice into an immutable string via the global interner pool.
func InternString(b []byte) string {
	return globalInterner.Intern(b)
}
