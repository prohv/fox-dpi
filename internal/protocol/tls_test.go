package protocol

import (
	"encoding/binary"
	"testing"
)

func buildTLSClientHello(serverName string) []byte {
	var body []byte

	// Client Version: TLS 1.2 (0x0303)
	body = append(body, 0x03, 0x03)
	// Random (32 bytes)
	body = append(body, make([]byte, 32)...)
	// Session ID: 0 length
	body = append(body, 0x00)
	// Cipher Suites (2 suites: 4 bytes)
	body = append(body, 0x00, 0x04, 0xc0, 0x2f, 0xc0, 0x30)
	// Compression: 1 method (null)
	body = append(body, 0x01, 0x00)

	// Build SNI Extension
	sniPayload := []byte{
		0x00, byte(len(serverName) + 3), // Server Name list length
		0x00,                            // Type: host_name
		byte(len(serverName) >> 8), byte(len(serverName)),
	}
	sniPayload = append(sniPayload, []byte(serverName)...)

	var extBuf []byte
	// Extension Type: 0x0000 (SNI)
	extBuf = append(extBuf, 0x00, 0x00)
	extBuf = append(extBuf, byte(len(sniPayload)>>8), byte(len(sniPayload)))
	extBuf = append(extBuf, sniPayload...)

	// Append Extensions length + Extensions
	body = append(body, byte(len(extBuf)>>8), byte(len(extBuf)))
	body = append(body, extBuf...)

	// Handshake header: Type 1 (ClientHello), Length (uint24)
	handshake := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	// Record header: Type 0x16, Version 0x0301, Length (uint16)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)

	return record
}

func Test_TLSDissector_ValidSNI(t *testing.T) {
	d := NewTLSDissector()
	raw := buildTLSClientHello("api.github.com")

	verdict, meta, err := d.Inspect(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictMatched {
		t.Fatalf("expected VerdictMatched, got %v", verdict)
	}
	if meta.Host != "api.github.com" {
		t.Fatalf("expected host api.github.com, got %s", meta.Host)
	}
	if meta.Details["sni"] != "api.github.com" {
		t.Fatalf("unexpected details: %+v", meta.Details)
	}
}

func Test_TLSDissector_FragmentedNeedMoreData(t *testing.T) {
	d := NewTLSDissector()
	raw := buildTLSClientHello("cloudflare.com")

	// Cut raw packet in half (simulating segment boundary)
	cut := raw[:len(raw)/2]

	verdict, _, err := d.Inspect(cut)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict != VerdictNeedMoreData {
		t.Fatalf("expected VerdictNeedMoreData for partial packet, got %v", verdict)
	}
}

func Test_TLSDissector_Malformed_NoPanic(t *testing.T) {
	d := NewTLSDissector()

	// Truncated extension length claiming 1000 bytes
	malformed := buildTLSClientHello("test.com")
	binary.BigEndian.PutUint16(malformed[len(malformed)-10:], 1000)

	cases := [][]byte{
		{},
		{0x16},
		{0x16, 0x03, 0x01, 0x00, 0x50, 0x01},
		malformed,
	}

	for i, c := range cases {
		_, _, _ = d.Inspect(c)
		_ = i
	}
}

func Benchmark_TLSDissector(b *testing.B) {
	d := NewTLSDissector()
	raw := buildTLSClientHello("api.github.com")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, _ = d.Inspect(raw)
	}
}
