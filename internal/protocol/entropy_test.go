package protocol

import (
	"math"
	"testing"
)

// standardShannonEntropy calculates reference entropy using standard math.Log2.
func standardShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

func Test_FastShannonEntropy_Equivalence(t *testing.T) {
	testCases := []string{
		"www",
		"google",
		"c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ",
		"production-worker-alpha-1234.us-east-1.compute.internal",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	for _, tc := range testCases {
		sample := tc
		if len(sample) > 63 {
			sample = sample[:63]
		}
		expected := standardShannonEntropy(sample)
		actual := FastShannonEntropy(sample)

		diff := math.Abs(expected - actual)
		if diff > 1e-9 {
			t.Errorf("[%s] entropy mismatch: expected %.6f, got %.6f (diff: %e)", sample, expected, actual, diff)
		}
	}
}

func Benchmark_Standard_ShannonEntropy(b *testing.B) {
	sample := "c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ"
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = standardShannonEntropy(sample)
	}
}

func Benchmark_Fast_ShannonEntropy_LUT(b *testing.B) {
	sample := "c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ"
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = FastShannonEntropy(sample)
	}
}
