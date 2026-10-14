package protocol

import (
	"testing"
)

func buildDNSQueryFixture(domain string, qtype uint16) []byte {
	buf := []byte{
		0xaa, 0xbb, // Transaction ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}

	parts := []string{"www", "google", "com"}
	if domain == "example.com" {
		parts = []string{"example", "com"}
	}

	for _, p := range parts {
		buf = append(buf, byte(len(p)))
		buf = append(buf, []byte(p)...)
	}
	buf = append(buf, 0x00) // End of QNAME

	buf = append(buf, byte(qtype>>8), byte(qtype)) // QTYPE
	buf = append(buf, 0x00, 0x01)                  // QCLASS (IN)
	return buf
}

func Test_DNSDissector_ValidQuery(t *testing.T) {
	d := NewDNSDissector()
	raw := buildDNSQueryFixture("www.google.com", 1) // Type A

	verdict, meta, err := d.Inspect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictMatched {
		t.Fatalf("expected VerdictMatched, got %v", verdict)
	}
	if meta.Host != "www.google.com" {
		t.Fatalf("expected host www.google.com, got %s", meta.Host)
	}
	if meta.Details["qtype"] != "A" || meta.Details["role"] != "query" {
		t.Fatalf("unexpected details: %+v", meta.Details)
	}
}

func Test_DNSDissector_TruncatedAndMalformed_NoPanic(t *testing.T) {
	d := NewDNSDissector()

	cases := [][]byte{
		{},
		{0x01, 0x02},
		make([]byte, 11),
		{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 'f', 'o', 'o'}, // truncated label
	}

	for i, c := range cases {
		v, _, err := d.Inspect(c)
		_ = err
		if len(c) < 12 && v != VerdictUnknown {
			t.Fatalf("case %d: expected VerdictUnknown, got %v", i, v)
		}
	}
}

func Benchmark_DNSDissector(b *testing.B) {
	d := NewDNSDissector()
	raw := buildDNSQueryFixture("www.google.com", 1)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = d.Inspect(raw)
	}
}
