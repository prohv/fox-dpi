package flow

import (
	"encoding/binary"
	"net/netip"
)

// FlowKey represents a canonical 5-tuple identifying a bidirectional transport flow.
type FlowKey struct {
	LowIP    netip.Addr
	HighIP   netip.Addr
	LowPort  uint16
	HighPort uint16
	Proto    uint8
}

// NewFlowKey canonicalizes endpoints so client->server and server->client match the same key.
func NewFlowKey(srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, proto uint8) FlowKey {
	cmp := srcIP.Compare(dstIP)
	if cmp < 0 || (cmp == 0 && srcPort <= dstPort) {
		return FlowKey{
			LowIP:    srcIP,
			HighIP:   dstIP,
			LowPort:  srcPort,
			HighPort: dstPort,
			Proto:    proto,
		}
	}
	return FlowKey{
		LowIP:    dstIP,
		HighIP:   srcIP,
		LowPort:  dstPort,
		HighPort: srcPort,
		Proto:    proto,
	}
}

// Hash returns a fast, zero-allocation 32-bit hash using 64-bit word mixing.
func (k FlowKey) Hash() uint32 {
	lowBytes := k.LowIP.As16()
	highBytes := k.HighIP.As16()

	low0 := binary.LittleEndian.Uint64(lowBytes[0:8])
	low1 := binary.LittleEndian.Uint64(lowBytes[8:16])
	high0 := binary.LittleEndian.Uint64(highBytes[0:8])
	high1 := binary.LittleEndian.Uint64(highBytes[8:16])
	ports := uint64(k.LowPort)<<32 | uint64(k.HighPort)<<16 | uint64(k.Proto)

	// Word mixing with 64-bit primes and avalanche shifts
	h := low0 ^ (low1 * 0x9e3779b97f4a7c15)
	h ^= high0 * 0xc6a4a7935bd1e995
	h ^= high1 * 0x85ebca6b
	h ^= ports

	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33

	return uint32(h ^ (h >> 32))
}
