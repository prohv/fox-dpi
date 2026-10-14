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

// Hash returns a fast, zero-allocation 32-bit hash for shard distribution.
func (k FlowKey) Hash() uint32 {
	const offset32 = 2166136261
	const prime32 = 16777619

	h := uint32(offset32)

	lowBytes := k.LowIP.As16()
	for i := 0; i < 16; i++ {
		h ^= uint32(lowBytes[i])
		h *= prime32
	}

	highBytes := k.HighIP.As16()
	for i := 0; i < 16; i++ {
		h ^= uint32(highBytes[i])
		h *= prime32
	}

	var ports [5]byte
	binary.BigEndian.PutUint16(ports[0:2], k.LowPort)
	binary.BigEndian.PutUint16(ports[2:4], k.HighPort)
	ports[4] = k.Proto

	for i := 0; i < 5; i++ {
		h ^= uint32(ports[i])
		h *= prime32
	}

	return h
}
