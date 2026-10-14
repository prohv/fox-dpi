package flow

import (
	"net/netip"
	"testing"
)

func Test_FlowKey_CanonicalInvariance(t *testing.T) {
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("10.0.0.1")

	// IPv4 different addresses
	k1 := NewFlowKey(ip1, 54321, ip2, 443, 6)
	k2 := NewFlowKey(ip2, 443, ip1, 54321, 6)

	if k1 != k2 {
		t.Fatalf("expected k1 == k2, got k1=%+v, k2=%+v", k1, k2)
	}

	// IPv6 different addresses
	ip6A := netip.MustParseAddr("2001:db8::1")
	ip6B := netip.MustParseAddr("2001:db8::2")
	k6A := NewFlowKey(ip6A, 8080, ip6B, 9090, 6)
	k6B := NewFlowKey(ip6B, 9090, ip6A, 8080, 6)

	if k6A != k6B {
		t.Fatalf("expected IPv6 invariance, got %+v vs %+v", k6A, k6B)
	}

	// Localhost tie-break by port
	local := netip.MustParseAddr("127.0.0.1")
	kLocal1 := NewFlowKey(local, 10000, local, 20000, 6)
	kLocal2 := NewFlowKey(local, 20000, local, 10000, 6)

	if kLocal1 != kLocal2 {
		t.Fatalf("expected localhost port tie-break invariance, got %+v vs %+v", kLocal1, kLocal2)
	}

	// Protocol difference
	kUDP := NewFlowKey(ip1, 54321, ip2, 443, 17)
	if k1 == kUDP {
		t.Fatal("expected TCP and UDP keys to differ")
	}
}

func Test_FlowKey_HashDeterminismAndDistribution(t *testing.T) {
	ip1 := netip.MustParseAddr("192.168.1.50")
	ip2 := netip.MustParseAddr("1.1.1.1")

	k1 := NewFlowKey(ip1, 40000, ip2, 53, 17)
	k2 := NewFlowKey(ip2, 53, ip1, 40000, 17)

	if k1.Hash() != k2.Hash() {
		t.Fatalf("expected identical hash for both directions, got %d vs %d", k1.Hash(), k2.Hash())
	}

	shard1 := k1.Hash() & 63
	shard2 := k2.Hash() & 63
	if shard1 != shard2 {
		t.Fatalf("expected identical shard index %d vs %d", shard1, shard2)
	}
}

func Benchmark_NewFlowKey(b *testing.B) {
	ip1 := netip.MustParseAddr("192.168.1.100")
	ip2 := netip.MustParseAddr("142.250.190.46")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = NewFlowKey(ip1, 51234, ip2, 443, 6)
	}
}

func Benchmark_FlowKey_Hash(b *testing.B) {
	ip1 := netip.MustParseAddr("192.168.1.100")
	ip2 := netip.MustParseAddr("142.250.190.46")
	k := NewFlowKey(ip1, 51234, ip2, 443, 6)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = k.Hash()
	}
}
