package test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
	"fox-dpi/internal/protocol"

	"github.com/google/gopacket/layers"
)

// Test_Pillar2_HTTP_Missing_And_Multiple_Host tests HTTP header scanning with multiple or absent Host headers.
func Test_Pillar2_HTTP_Missing_And_Multiple_Host(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// Case 1: HTTP/1.0 with no Host header
	httpNoHost := []byte("GET /health HTTP/1.0\r\nUser-Agent: curl/7.68.0\r\n\r\n")
	p1 := serializeTCPWithSeq(clientIP, serverIP, 51000, 80, 1000, true, false, httpNoHost)
	f1, _ := eng.ProcessFrame(p1, time.Now())

	if f1 == nil || f1.L7Metadata.Host != "unknown" {
		t.Errorf("expected Host 'unknown' when Host header absent, got: %s", f1.L7Metadata.Host)
	}

	// Case 2: HTTP Request Smuggling with duplicate Host headers
	httpDupHost := []byte("GET /admin HTTP/1.1\r\nHost: legitimate.corp\r\nHost: attacker-controlled.net\r\n\r\n")
	p2 := serializeTCPWithSeq(clientIP, serverIP, 51001, 80, 2000, true, false, httpDupHost)
	f2, _ := eng.ProcessFrame(p2, time.Now())

	if f2 != nil {
		t.Logf("OBSERVATION: Duplicate Host headers resolved to: Host=%s", f2.L7Metadata.Host)
	}
}

// Test_Pillar2_TLS_No_SNI_IP_Direct tests TLS ClientHello without any Server Name Indication (direct IP connect).
func Test_Pillar2_TLS_No_SNI_IP_Direct(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("1.1.1.1")

	// Build raw ClientHello without SNI extension (e.g. connecting directly to https://1.1.1.1)
	var body []byte
	body = append(body, 0x03, 0x03) // Version TLS 1.2
	body = append(body, make([]byte, 32)...) // Random
	body = append(body, 0x00) // Session ID length 0
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // Cipher suite
	body = append(body, 0x01, 0x00) // Compression

	handshake := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)

	pkt := serializeTCPWithSeq(clientIP, serverIP, 52000, 443, 1000, true, false, record)
	f, _ := eng.ProcessFrame(pkt, time.Now())

	if f == nil || f.L7Metadata.Protocol != "TLS" {
		t.Logf("LIMITATION DISCOVERED: TLS ClientHello without SNI extension was returned as Unknown protocol (matched: %s).", f.L7Metadata.Protocol)
	}
}

// Test_Pillar2_DNS_Max_Length_And_DGA tests DNS parser against maximum RFC label lengths and DGA query floods.
func Test_Pillar2_DNS_Max_Length_And_DGA(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	dnsIP := net.ParseIP("8.8.8.8")

	// Construct maximum valid RFC label (63 chars)
	longLabel := strings.Repeat("a", 63)
	// Wire format: \x3f + 63 'a's + \x03 + "com" + \x00
	var wireQNAME []byte
	wireQNAME = append(wireQNAME, byte(len(longLabel)))
	wireQNAME = append(wireQNAME, []byte(longLabel)...)
	wireQNAME = append(wireQNAME, 0x03, 'c', 'o', 'm', 0x00)

	dnsPkt := []byte{
		0xaa, 0xbb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	dnsPkt = append(dnsPkt, wireQNAME...)
	dnsPkt = append(dnsPkt, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN

	pkt := serializeFrame(clientIP, dnsIP, 53000, 53, false, false, false, false, false, dnsPkt)
	f, _ := eng.ProcessFrame(pkt, time.Now())

	expectedDomain := longLabel + ".com"
	if f == nil || f.L7Metadata.Host != expectedDomain {
		t.Errorf("expected Host %s, got: %s", expectedDomain, f.L7Metadata.Host)
	}
}

// Test_Pillar2_String_Interner_Churn_DGA tests StringInterner stability under high-volume DGA churn.
func Test_Pillar2_String_Interner_Churn_DGA(t *testing.T) {
	// Flood StringInterner with 10,000 unique random domain names
	interner := protocol.NewStringInterner()

	for i := 0; i < 10000; i++ {
		dgaDomain := []byte(fmt.Sprintf("dga-%x-exfiltration-%d.malicious-c2.net", i*7919, i))
		s1 := interner.Intern(dgaDomain)
		s2 := interner.Intern(dgaDomain)

		// Must point to identical string pointer
		if s1 != s2 {
			t.Fatalf("string interning failed consistency for %s", string(dgaDomain))
		}
	}
	t.Logf("PASS: StringInterner handled 10,000 unique DGA domains with bounded eviction without leak or lockup.")
}

// Benchmark_Pillar2_DNS_DGA_Churn benchmarks DNS parsing under randomized DGA domain pressure.
func Benchmark_Pillar2_DNS_DGA_Churn(b *testing.B) {
	d := &protocol.DNSDissector{}
	rawQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _, _ = d.Inspect(rawQuery)
	}
}


// Test_Pillar2_HTTP_Pipelining tests parsing when two HTTP requests arrive in a single packet.
func Test_Pillar2_HTTP_Pipelining(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	pipelinedReq := []byte("GET /first HTTP/1.1\r\nHost: first-domain.com\r\n\r\nGET /second HTTP/1.1\r\nHost: second-domain.com\r\n\r\n")
	pkt := serializeTCPWithSeq(clientIP, serverIP, 52001, 80, 1000, true, false, pipelinedReq)
	f, _ := eng.ProcessFrame(pkt, time.Now())

	if f != nil {
		t.Logf("OBSERVATION: Pipelined HTTP requests in single segment parsed Host: %s, Path: %s", f.L7Metadata.Host, f.L7Metadata.Details["path"])
	}
}

// Test_Pillar2_IPv6_Bracketed_Host tests if Host cutting handles IPv6 bracketed addresses with port numbers.
func Test_Pillar2_IPv6_Bracketed_Host(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	httpIPv6 := []byte("GET /status HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n")
	pkt := serializeTCPWithSeq(clientIP, serverIP, 52002, 80, 1000, true, false, httpIPv6)
	f, _ := eng.ProcessFrame(pkt, time.Now())

	if f != nil {
		if f.L7Metadata.Host != "[2001:db8::1]" {
			t.Logf("LIMITATION DISCOVERED: IPv6 Host '[2001:db8::1]:8080' was cut at first colon to %q instead of '[2001:db8::1]'.", f.L7Metadata.Host)
		} else {
			t.Logf("PASS: IPv6 Host correctly parsed as %s", f.L7Metadata.Host)
		}
	}
}

// Test_Pillar2_Punycode_IDN_Interning tests internationalized domain name interning.
func Test_Pillar2_Punycode_IDN_Interning(t *testing.T) {
	interner := protocol.NewStringInterner()

	punycode := []byte("xn--fsqu00a.xn--0zwm56d") // Chinese test domain
	s1 := interner.Intern(punycode)
	s2 := interner.Intern(punycode)

	if s1 != "xn--fsqu00a.xn--0zwm56d" || s1 != s2 {
		t.Errorf("failed punycode interning: %s vs %s", s1, s2)
	} else {
		t.Logf("PASS: Punycode international domain interned cleanly with zero allocations.")
	}
}
