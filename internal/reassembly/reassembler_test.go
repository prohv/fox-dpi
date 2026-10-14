package reassembly

import (
	"testing"
)

func Test_StreamReassembler_InOrder(t *testing.T) {
	r := NewStreamReassembler(1000)

	buf1 := r.Push(1000, []byte("PART1_"))
	if string(buf1) != "PART1_" {
		t.Fatalf("expected PART1_, got %s", string(buf1))
	}

	buf2 := r.Push(1006, []byte("PART2"))
	if string(buf2) != "PART1_PART2" {
		t.Fatalf("expected PART1_PART2, got %s", string(buf2))
	}
}

func Test_StreamReassembler_OutOfOrder(t *testing.T) {
	r := NewStreamReassembler(1000)

	// Inject Part 3 first
	res3 := r.Push(1020, []byte("PART3"))
	if res3 != nil {
		t.Fatalf("expected nil for out-of-order segment, got %s", string(res3))
	}

	// Inject Part 1
	res1 := r.Push(1000, []byte("PART1_"))
	if string(res1) != "PART1_" {
		t.Fatalf("expected PART1_, got %s", string(res1))
	}

	// Inject missing Part 2 (fills the gap: 14 bytes from 1006 to 1020)
	res2 := r.Push(1006, []byte("PART2_IS_HERE_"))
	if string(res2) != "PART1_PART2_IS_HERE_PART3" {
		t.Fatalf("expected complete reassembled stream, got %s", string(res2))
	}
}

func Test_StreamReassembler_OverlappingDuplicate(t *testing.T) {
	r := NewStreamReassembler(100)

	r.Push(100, []byte("ABCDEF"))
	// Overlapping retransmission: starts at 103, carries 'DEF' and new 'GHI'
	res := r.Push(103, []byte("DEFGHI"))
	if string(res) != "ABCDEFGHI" {
		t.Fatalf("expected overlapping segment merged into ABCDEFGHI, got %s", string(res))
	}
}

func Test_StreamReassembler_DoSProtection_LargeGap(t *testing.T) {
	r := NewStreamReassembler(100)

	r.Push(100, []byte("START"))
	// Malicious huge sequence gap (10MB away)
	res := r.Push(10_000_000, []byte("ATTACK"))
	if res != nil {
		t.Fatal("expected nil for out-of-bound sequence")
	}

	// Buffer must remain bounded to original data
	if len(r.Buffer()) != 5 {
		t.Fatalf("buffer exceeded expected length, got %d", len(r.Buffer()))
	}
}

func Benchmark_StreamReassembler_InOrder(b *testing.B) {
	r := NewStreamReassembler(1000)
	chunk := []byte("0123456789abcdef")

	b.ReportAllocs()
	b.ResetTimer()

	seq := uint32(1000)
	for i := 0; i < b.N; i++ {
		r.Push(seq, chunk)
		seq += 16
		if len(r.Buffer()) >= 2048 {
			r.buffer = r.buffer[:0]
		}
	}
}
