package protocol

import (
	"testing"
)

func Test_Dispatcher_Routing(t *testing.T) {
	disp := NewDispatcher()

	// 1. DNS dispatch
	dnsPayload := buildDNSQueryFixture("www.google.com", 1)
	vDNS, metaDNS, err := disp.Dispatch(dnsPayload, 17)
	if err != nil || vDNS != VerdictMatched || metaDNS.Protocol != "DNS" {
		t.Fatalf("expected DNS dispatch match, got %v, meta=%+v, err=%v", vDNS, metaDNS, err)
	}

	// 2. TLS dispatch
	tlsPayload := buildTLSClientHello("cloudflare.com")
	vTLS, metaTLS, err := disp.Dispatch(tlsPayload, 6)
	if err != nil || vTLS != VerdictMatched || metaTLS.Protocol != "TLS" {
		t.Fatalf("expected TLS dispatch match, got %v, meta=%+v, err=%v", vTLS, metaTLS, err)
	}

	// 3. HTTP dispatch
	httpPayload := []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
	vHTTP, metaHTTP, err := disp.Dispatch(httpPayload, 6)
	if err != nil || vHTTP != VerdictMatched || metaHTTP.Protocol != "HTTP" {
		t.Fatalf("expected HTTP dispatch match, got %v, meta=%+v, err=%v", vHTTP, metaHTTP, err)
	}

	// 4. Unknown junk rejection
	junk := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	vJunk, _, err := disp.Dispatch(junk, 6)
	if err != nil || vJunk != VerdictUnknown {
		t.Fatalf("expected VerdictUnknown for junk, got %v, err=%v", vJunk, err)
	}
}

func Benchmark_Dispatcher_FastRejection(b *testing.B) {
	disp := NewDispatcher()
	junk := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = disp.Dispatch(junk, 6)
	}
}
