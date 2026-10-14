package protocol

import (
	"testing"
)

func Test_HTTPDissector_ValidGet(t *testing.T) {
	d := NewHTTPDissector()
	raw := []byte("GET /api/v1/users HTTP/1.1\r\nHost: api.service.internal:8080\r\nUser-Agent: Go-http-client/1.1\r\nAccept: application/json\r\n\r\n")

	v, meta, err := d.Inspect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VerdictMatched {
		t.Fatalf("expected VerdictMatched, got %v", v)
	}
	if meta.Host != "api.service.internal" {
		t.Fatalf("expected host api.service.internal, got %s", meta.Host)
	}
	if meta.Details["method"] != "GET" || meta.Details["path"] != "/api/v1/users" {
		t.Fatalf("unexpected details: %+v", meta.Details)
	}
	if meta.Details["user_agent"] != "Go-http-client/1.1" {
		t.Fatalf("unexpected user-agent: %s", meta.Details["user_agent"])
	}
}

func Test_HTTPDissector_IncompleteNeedMoreData(t *testing.T) {
	d := NewHTTPDissector()
	// Split midway before double CRLF
	raw := []byte("POST /upload HTTP/1.1\r\nHost: files.org\r\nContent-Length: 100")

	v, _, err := d.Inspect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != VerdictNeedMoreData {
		t.Fatalf("expected VerdictNeedMoreData, got %v", v)
	}
}

func Test_HTTPDissector_NonHTTP(t *testing.T) {
	d := NewHTTPDissector()
	cases := [][]byte{
		{},
		{0x16, 0x03, 0x01},
		[]byte("SSH-2.0-OpenSSH_8.2p1"),
		[]byte("INVALID / HTTP/1.1\r\n\r\n"),
	}

	for i, c := range cases {
		v, _, _ := d.Inspect(c)
		if v != VerdictUnknown {
			t.Fatalf("case %d: expected VerdictUnknown, got %v", i, v)
		}
	}
}

func Benchmark_HTTPDissector(b *testing.B) {
	d := NewHTTPDissector()
	raw := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 Chrome/110.0\r\n\r\n")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = d.Inspect(raw)
	}
}
