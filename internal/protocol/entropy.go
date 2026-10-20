package protocol

import (
	"math"
)

// Precomputed lookup tables for Shannon Entropy acceleration.
// By RFC 1035, a single DNS label is strictly bounded to <= 63 bytes.
// Any character count c is strictly an integer in [0, 63], eliminating all runtime math.Log2 calls.
var (
	cLog2Table [64]float64
	log2Table  [64]float64
)

func init() {
	for c := 1; c < 64; c++ {
		cLog2Table[c] = float64(c) * math.Log2(float64(c))
		log2Table[c] = math.Log2(float64(c))
	}
}

// FastShannonEntropy computes mathematically exact Shannon entropy (bits per byte)
// for strings up to 63 bytes using a precomputed logarithmic lookup table (LUT).
// Zero heap allocations.
func FastShannonEntropy(s string) float64 {
	n := len(s)
	if n <= 1 {
		return 0.0
	}
	if n >= 64 {
		n = 63
	}

	var counts [256]uint8
	var unique [64]uint8
	numUnique := 0

	for i := 0; i < n; i++ {
		b := s[i]
		if counts[b] == 0 {
			unique[numUnique] = b
			numUnique++
		}
		counts[b]++
	}

	sum := 0.0
	for i := 0; i < numUnique; i++ {
		c := counts[unique[i]]
		if c >= 64 {
			c = 63
		}
		sum += cLog2Table[c]
	}

	return log2Table[n] - (sum / float64(n))
}
