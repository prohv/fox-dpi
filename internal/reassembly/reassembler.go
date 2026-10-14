package reassembly

import (
	"sort"
)

// MaxBufferSize caps buffer growth to 4 KB to prevent Reassembly Memory Exhaustion DoS.
const MaxBufferSize = 4096

type segment struct {
	seq  uint32
	data []byte
}

// StreamReassembler tracks TCP sequence numbers and stitches out-of-order segments within a 4 KB window.
type StreamReassembler struct {
	nextSeq     uint32
	initialized bool
	disabled    bool
	buffer      []byte
	pending     []segment
}

// NewStreamReassembler initializes an empty bounded reassembler.
// If baseSeq is provided (from SYN), it establishes the expected starting sequence.
func NewStreamReassembler(baseSeq uint32) *StreamReassembler {
	return &StreamReassembler{
		nextSeq:     baseSeq,
		initialized: baseSeq != 0,
		buffer:      make([]byte, 0, 1024),
		pending:     make([]segment, 0, 8),
	}
}

// Push ingests a TCP payload at the specified sequence number and returns the contiguous buffer.
func (r *StreamReassembler) Push(seq uint32, data []byte) []byte {
	if r.disabled || len(data) == 0 {
		return nil
	}

	if !r.initialized {
		r.initialized = true
		r.nextSeq = seq + uint32(len(data))
		r.buffer = append(r.buffer, data...)
		r.drainPending()
		return r.checkLimit()
	}

	// Case 1: In-order contiguous packet
	if seq == r.nextSeq {
		r.buffer = append(r.buffer, data...)
		r.nextSeq += uint32(len(data))
		r.drainPending()
		return r.checkLimit()
	}

	// Case 2: Overlapping segment or retransmission
	if seq < r.nextSeq {
		endSeq := seq + uint32(len(data))
		if endSeq > r.nextSeq {
			offset := r.nextSeq - seq
			newData := data[offset:]
			r.buffer = append(r.buffer, newData...)
			r.nextSeq = endSeq
			r.drainPending()
			return r.checkLimit()
		}
		// Pure duplicate, ignore
		return r.buffer
	}

	// Case 3: Out-of-order packet (future sequence)
	// Guard against DoS: do not hold packets beyond 4 KB from nextSeq
	if seq-r.nextSeq <= MaxBufferSize && len(r.pending) < 16 {
		copied := make([]byte, len(data))
		copy(copied, data)
		r.pending = append(r.pending, segment{seq: seq, data: copied})
		sort.Slice(r.pending, func(i, j int) bool {
			return r.pending[i].seq < r.pending[j].seq
		})
	}

	return nil // Waiting for missing gap
}

// drainPending flushes any out-of-order segments that now connect contiguously.
func (r *StreamReassembler) drainPending() {
	for len(r.pending) > 0 {
		first := r.pending[0]
		if first.seq == r.nextSeq {
			r.buffer = append(r.buffer, first.data...)
			r.nextSeq += uint32(len(first.data))
			r.pending = r.pending[1:]
		} else if first.seq < r.nextSeq {
			endSeq := first.seq + uint32(len(first.data))
			if endSeq > r.nextSeq {
				offset := r.nextSeq - first.seq
				r.buffer = append(r.buffer, first.data[offset:]...)
				r.nextSeq = endSeq
			}
			r.pending = r.pending[1:]
		} else {
			// Gap still exists
			break
		}
	}
}

func (r *StreamReassembler) checkLimit() []byte {
	if len(r.buffer) > MaxBufferSize {
		r.disabled = true
		r.buffer = r.buffer[:MaxBufferSize]
	}
	return r.buffer
}

// Reset clears and frees buffer memory once dissection succeeds.
func (r *StreamReassembler) Reset() {
	r.buffer = nil
	r.pending = nil
	r.disabled = true
}

// Buffer returns current contiguous stream data.
func (r *StreamReassembler) Buffer() []byte {
	return r.buffer
}
