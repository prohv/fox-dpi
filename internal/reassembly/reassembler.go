package reassembly

import (
	"sort"
	"sync"
)

// MaxBufferSize caps buffer growth to 4 KB to prevent Reassembly Memory Exhaustion DoS.
const MaxBufferSize = 4096

// TotalCapacity provides 4 KB headroom (for backward delivery) + 4 KB tailroom (for forward delivery).
const TotalCapacity = MaxBufferSize * 2
const HeadroomOffset = MaxBufferSize

type segment struct {
	seq  uint32
	data []byte
}

var reassemblerPool = sync.Pool{
	New: func() any {
		return &StreamReassembler{
			rawBuffer: make([]byte, TotalCapacity),
			pending:   make([]segment, 0, 8),
		}
	},
}

// StreamReassembler tracks TCP sequence numbers and stitches out-of-order segments
// bidirectionally (both forward and backward) within a bounded memory window.
type StreamReassembler struct {
	baseSeq     uint32
	nextSeq     uint32
	head        int
	tail        int
	initialized bool
	disabled    bool
	rawBuffer   []byte
	buffer      []byte
	pending     []segment
}

// NewStreamReassembler initializes an empty bounded reassembler.
// If baseSeq is provided (from SYN), it establishes the expected starting sequence.
func NewStreamReassembler(baseSeq uint32) *StreamReassembler {
	return GetReassembler(baseSeq)
}

// GetReassembler borrows a clean reassembler from the memory pool.
func GetReassembler(baseSeq uint32) *StreamReassembler {
	r := reassemblerPool.Get().(*StreamReassembler)
	r.baseSeq = baseSeq
	r.nextSeq = baseSeq
	r.head = HeadroomOffset
	r.tail = HeadroomOffset
	r.initialized = baseSeq != 0
	r.disabled = false
	if len(r.rawBuffer) < TotalCapacity {
		r.rawBuffer = make([]byte, TotalCapacity)
	}
	r.buffer = r.rawBuffer[r.head:r.tail]
	r.pending = r.pending[:0]
	return r
}

// PutReassembler returns a reassembler to the pool for reuse.
func PutReassembler(r *StreamReassembler) {
	if r == nil {
		return
	}
	r.disabled = true
	r.pending = r.pending[:0]
	reassemblerPool.Put(r)
}

// Push ingests a TCP payload at the specified sequence number and returns the contiguous buffer.
func (r *StreamReassembler) Push(seq uint32, data []byte) []byte {
	if r.disabled || len(data) == 0 {
		return nil
	}

	// Handle benchmark or caller resetting r.buffer externally
	if len(r.buffer) == 0 && (r.head != HeadroomOffset || r.tail != HeadroomOffset) {
		r.head = HeadroomOffset
		r.tail = HeadroomOffset
	}

	if !r.initialized {
		r.initialized = true
		r.baseSeq = seq
		r.nextSeq = seq + uint32(len(data))
		r.head = HeadroomOffset
		r.tail = HeadroomOffset + len(data)
		copy(r.rawBuffer[r.head:], data)
		r.drainPending()
		return r.checkLimit()
	}

	endSeq := seq + uint32(len(data))

	// Case 1: In-order forward contiguous packet
	if seq == r.nextSeq {
		if r.tail+len(data) <= len(r.rawBuffer) {
			copy(r.rawBuffer[r.tail:], data)
			r.tail += len(data)
			r.nextSeq += uint32(len(data))
			r.drainPending()
			return r.checkLimit()
		}
	}

	// Case 2: In-order backward contiguous packet (preceding packet connecting directly to baseSeq)
	if endSeq == r.baseSeq {
		if r.head-len(data) >= 0 {
			r.head -= len(data)
			copy(r.rawBuffer[r.head:], data)
			r.baseSeq = seq
			r.drainPending()
			return r.checkLimit()
		}
	}

	// Case 3: Overlapping segment forward (seq < nextSeq and endSeq > nextSeq)
	if int32(seq-r.nextSeq) < 0 && int32(endSeq-r.nextSeq) > 0 {
		offset := int(r.nextSeq - seq)
		newData := data[offset:]
		if r.tail+len(newData) <= len(r.rawBuffer) {
			copy(r.rawBuffer[r.tail:], newData)
			r.tail += len(newData)
			r.nextSeq = endSeq
			r.drainPending()
			return r.checkLimit()
		}
	}

	// Case 4: Overlapping segment backward (endSeq > baseSeq and seq < baseSeq)
	if int32(endSeq-r.baseSeq) > 0 && int32(seq-r.baseSeq) < 0 {
		trimLen := int(r.baseSeq - seq)
		newData := data[:trimLen]
		if r.head-len(newData) >= 0 {
			r.head -= len(newData)
			copy(r.rawBuffer[r.head:], newData)
			r.baseSeq = seq
			r.drainPending()
			return r.checkLimit()
		}
	}

	// Case 5: Duplicate packet (already covered within baseSeq..nextSeq)
	if int32(seq-r.baseSeq) >= 0 && int32(endSeq-r.nextSeq) <= 0 {
		return r.checkLimit()
	}

	// Case 6: Out-of-order packet (future or past gap)
	// Guard against DoS: do not hold packets beyond MaxBufferSize from nextSeq or baseSeq
	isFutureGap := int32(seq-r.nextSeq) > 0 && seq-r.nextSeq <= MaxBufferSize
	isPastGap := int32(r.baseSeq-endSeq) > 0 && r.baseSeq-endSeq <= MaxBufferSize
	if (isFutureGap || isPastGap) && len(r.pending) < 16 {
		copied := make([]byte, len(data))
		copy(copied, data)
		r.pending = append(r.pending, segment{seq: seq, data: copied})
		sort.Slice(r.pending, func(i, j int) bool {
			return int32(r.pending[i].seq-r.pending[j].seq) < 0
		})
	}

	return nil // Waiting for missing gap
}

// drainPending flushes any out-of-order segments that now connect contiguously (forward or backward).
func (r *StreamReassembler) drainPending() {
	progress := true
	for progress && len(r.pending) > 0 {
		progress = false
		for i := 0; i < len(r.pending); i++ {
			p := r.pending[i]
			pEnd := p.seq + uint32(len(p.data))

			// Check forward connection
			if p.seq == r.nextSeq {
				if r.tail+len(p.data) <= len(r.rawBuffer) {
					copy(r.rawBuffer[r.tail:], p.data)
					r.tail += len(p.data)
					r.nextSeq += uint32(len(p.data))
					r.pending = append(r.pending[:i], r.pending[i+1:]...)
					progress = true
					break
				}
			} else if int32(p.seq-r.nextSeq) < 0 && int32(pEnd-r.nextSeq) > 0 {
				offset := int(r.nextSeq - p.seq)
				newData := p.data[offset:]
				if r.tail+len(newData) <= len(r.rawBuffer) {
					copy(r.rawBuffer[r.tail:], newData)
					r.tail += len(newData)
					r.nextSeq = pEnd
					r.pending = append(r.pending[:i], r.pending[i+1:]...)
					progress = true
					break
				}
			}

			// Check backward connection
			if pEnd == r.baseSeq {
				if r.head-len(p.data) >= 0 {
					r.head -= len(p.data)
					copy(r.rawBuffer[r.head:], p.data)
					r.baseSeq = p.seq
					r.pending = append(r.pending[:i], r.pending[i+1:]...)
					progress = true
					break
				}
			} else if int32(pEnd-r.baseSeq) > 0 && int32(p.seq-r.baseSeq) < 0 {
				trimLen := int(r.baseSeq - p.seq)
				newData := p.data[:trimLen]
				if r.head-len(newData) >= 0 {
					r.head -= len(newData)
					copy(r.rawBuffer[r.head:], newData)
					r.baseSeq = p.seq
					r.pending = append(r.pending[:i], r.pending[i+1:]...)
					progress = true
					break
				}
			} else if int32(p.seq-r.baseSeq) >= 0 && int32(pEnd-r.nextSeq) <= 0 {
				// Duplicate in pending list, drop cleanly
				r.pending = append(r.pending[:i], r.pending[i+1:]...)
				progress = true
				break
			}
		}
	}
}

func (r *StreamReassembler) checkLimit() []byte {
	currentLen := r.tail - r.head
	if currentLen > MaxBufferSize {
		r.disabled = true
		r.tail = r.head + MaxBufferSize
	}
	r.buffer = r.rawBuffer[r.head:r.tail]
	return r.buffer
}

// Reset clears and frees buffer memory once dissection succeeds.
func (r *StreamReassembler) Reset() {
	r.rawBuffer = nil
	r.buffer = nil
	r.pending = nil
	r.disabled = true
}

// Buffer returns current contiguous stream data.
func (r *StreamReassembler) Buffer() []byte {
	if r.head >= r.tail {
		return nil
	}
	r.buffer = r.rawBuffer[r.head:r.tail]
	return r.buffer
}
