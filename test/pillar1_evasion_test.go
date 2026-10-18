package test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
	"fox-dpi/internal/sink"

	"github.com/google/gopacket/layers"
)

// captureSink collects emitted alerts and flows in-memory for assertion.
type captureSink struct {
	sink.NoopSink
	alerts []sink.AlertEvent
	flows  []sink.FlowEvent
}

func (s *captureSink) EmitAlert(e sink.AlertEvent) {
	s.alerts = append(s.alerts, e)
}

func (s *captureSink) EmitFlow(e sink.FlowEvent) {
	s.flows = append(s.flows, e)
}

// Test_Pillar1_Adversarial_TCP_Segmentation verifies TLS port-spoof detection
// when the ClientHello is chopped into tiny 3-byte TCP segments across 10 packets.
func Test_Pillar1_Adversarial_TCP_Segmentation(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.0.0.100")
	serverIP := net.ParseIP("198.51.100.50")
	clientPort := uint16(49152)
	serverPort := uint16(80) // Spoofed HTTP port

	// 1. Establish 3-Way Handshake
	now := time.Now()
	syn := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, true, false, false, false, nil)
	synAck := serializeFrame(serverIP, clientIP, serverPort, clientPort, true, true, true, false, false, nil)
	ack := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, false, true, false, false, nil)

	_, _ = eng.ProcessFrame(syn, now)
	_, _ = eng.ProcessFrame(synAck, now.Add(5*time.Millisecond))
	_, _ = eng.ProcessFrame(ack, now.Add(10*time.Millisecond))

	// 2. Stream fragmented TLS ClientHello across tiny 3-byte segments
	rawTLS := buildTestTLSClientHello("covert-c2.adversary.org")
	seq := uint32(1000)
	chunkSize := 3

	for i := 0; i < len(rawTLS); i += chunkSize {
		end := i + chunkSize
		if end > len(rawTLS) {
			end = len(rawTLS)
		}
		chunk := rawTLS[i:end]
		pkt := serializeTCPWithSeq(clientIP, serverIP, clientPort, serverPort, seq+uint32(i), true, false, chunk)
		_, _ = eng.ProcessFrame(pkt, now.Add(time.Duration(15+i)*time.Millisecond))
	}

	_ = eng.Close()

	// Check whether PORT_SPOOF_TLS fired despite extreme TCP segmentation
	var foundSpoof bool
	for _, a := range snk.alerts {
		if a.Rule == "PORT_SPOOF_TLS" && a.DstPort == 80 {
			foundSpoof = true
			break
		}
	}

	if !foundSpoof {
		t.Errorf("LIMITATION: Failed to detect PORT_SPOOF_TLS across 3-byte TCP segments! Alerts: %+v", snk.alerts)
	}
}

// Test_Pillar1_C2_On_Arbitrary_High_Ports checks detection of TLS C2 on ports like 4444 (Metasploit) or 1337.
func Test_Pillar1_C2_On_Arbitrary_High_Ports(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("192.168.1.10")
	c2IP := net.ParseIP("203.0.113.88")
	clientPort := uint16(51515)
	c2Port := uint16(4444) // Metasploit default C2 listener

	now := time.Now()
	rawTLS := buildTestTLSClientHello("c2-beacon.darknet.internal")

	p1 := serializeFrame(clientIP, c2IP, clientPort, c2Port, true, true, false, false, false, nil)
	p2 := serializeTCPWithSeq(clientIP, c2IP, clientPort, c2Port, 1000, true, false, rawTLS)

	_, _ = eng.ProcessFrame(p1, now)
	f, _ := eng.ProcessFrame(p2, now.Add(10*time.Millisecond))
	_ = eng.Close()

	// Verify L7 identification
	if f == nil || f.L7Metadata.Protocol != "TLS" {
		t.Fatalf("Failed to recognize TLS protocol on port 4444, got: %+v", f)
	}

	// Verify whether PORT_SPOOF_TLS fired for arbitrary non-443/non-8443 port
	var foundAlert bool
	for _, a := range snk.alerts {
		if a.Rule == "PORT_SPOOF_TLS" && a.DstPort == 4444 {
			foundAlert = true
			break
		}
	}

	if !foundAlert {
		t.Logf("LIMITATION DISCOVERED: TLS on high port 4444 was recognized as TLS, but PORT_SPOOF_TLS rule only matches ports 80/8080.")
	}
}

// Test_Pillar1_Adversarial_HTTP_Segmentation tests split HTTP verbs on port 443.
func Test_Pillar1_Adversarial_HTTP_Segmentation(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.0.0.5")
	serverIP := net.ParseIP("10.0.0.6")
	clientPort := uint16(42000)
	serverPort := uint16(443) // Plaintext HTTP on HTTPS port

	now := time.Now()
	// Split "POST /exfil HTTP/1.1\r\nHost: target.corp\r\n\r\n" right in the verb:
	part1 := []byte("PO")
	part2 := []byte("ST /exfil HTTP/1.1\r\nHost: target.corp\r\n\r\n")

	p1 := serializeTCPWithSeq(clientIP, serverIP, clientPort, serverPort, 100, true, false, part1)
	p2 := serializeTCPWithSeq(clientIP, serverIP, clientPort, serverPort, 102, true, false, part2)

	_, _ = eng.ProcessFrame(p1, now)
	_, _ = eng.ProcessFrame(p2, now.Add(5*time.Millisecond))
	_ = eng.Close()

	var foundAlert bool
	for _, a := range snk.alerts {
		if a.Rule == "PORT_SPOOF_HTTP" {
			foundAlert = true
			break
		}
	}

	if !foundAlert {
		t.Logf("LIMITATION DISCOVERED: Fragmented HTTP verb across TCP packets did not trigger PORT_SPOOF_HTTP.")
	}
}

// Test_Pillar1_DNS_Compression_Loop_DoS tests parser defense against malicious cyclic DNS compression pointers.
func Test_Pillar1_DNS_Compression_Loop_DoS(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	dnsIP := net.ParseIP("1.1.1.1")

	// Craft malicious DNS payload with compression pointer looping back to itself:
	// Pointer 0xC0 0x0C points to offset 12 (itself)
	cyclicDNS := []byte{
		0x00, 0x01, // ID
		0x01, 0x00, // Flags (standard query)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		0xC0, 0x0C, // Compression pointer pointing to offset 12 -> INFINITE LOOP
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}

	pkt := serializeFrame(clientIP, dnsIP, 54321, 53, false, false, false, false, false, cyclicDNS)

	// Engine must process without hanging or crashing
	done := make(chan bool)
	go func() {
		_, _ = eng.ProcessFrame(pkt, time.Now())
		done <- true
	}()

	select {
	case <-done:
		t.Logf("PASS: DNS compression pointer loop was defended against without infinite loop or panic.")
	case <-time.After(1 * time.Second):
		t.Fatalf("FAIL: DNS parser entered infinite loop on cyclic compression pointer!")
	}
}

// Test_Pillar1_Junk_Prefix_Evasion evaluates what happens when malware prepends junk noise before TLS.
func Test_Pillar1_Junk_Prefix_Evasion(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.0.0.1")
	c2IP := net.ParseIP("198.51.100.1")

	// Prepend 16 bytes of random junk before real TLS ClientHello
	junk := bytes.Repeat([]byte{0xAA}, 16)
	realTLS := buildTestTLSClientHello("hidden-c2.evil.com")
	evasivePayload := append(junk, realTLS...)

	pkt := serializeTCPWithSeq(clientIP, c2IP, 55555, 80, 1000, true, false, evasivePayload)
	f, _ := eng.ProcessFrame(pkt, time.Now())

	if f == nil || f.L7Metadata.Protocol != "TLS" {
		t.Logf("LIMITATION DISCOVERED: Prepending 16 junk bytes before TLS bypasses magic-byte dispatcher (matched: %s).", f.L7Metadata.Protocol)
	}
}

// Benchmark_Pillar1_Adversarial_Fragmentation measures throughput under heavy TCP stream fragmentation.
func Benchmark_Pillar1_Adversarial_Fragmentation(b *testing.B) {
	snk := &captureSink{}
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")
	rawTLS := buildTestTLSClientHello("benchmark-c2.example.com")

	p1 := serializeTCPWithSeq(clientIP, serverIP, 50000, 80, 1000, true, false, rawTLS[:10])
	p2 := serializeTCPWithSeq(clientIP, serverIP, 50000, 80, 1010, true, false, rawTLS[10:])

	now := time.Now()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = eng.ProcessFrame(p1, now)
		_, _ = eng.ProcessFrame(p2, now)
	}
}


// Test_Pillar1_Overlapping_Conflicting_Segments tests TCP reassembly behavior
// when an attacker sends overlapping segments with conflicting data (Ptacek-Newsham evasion).
func Test_Pillar1_Overlapping_Conflicting_Segments(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// Segment 1: Seq 1000..1010 "GET /secret"
	p1 := serializeTCPWithSeq(clientIP, serverIP, 49999, 80, 1000, true, false, []byte("GET /secret"))
	// Segment 2: Seq 1005..1020 Conflicting overlap "XXXXX /fake"
	p2 := serializeTCPWithSeq(clientIP, serverIP, 49999, 80, 1005, true, false, []byte("XXXXX /fake HTTP/1.1\r\n\r\n"))

	_, _ = eng.ProcessFrame(p1, time.Now())
	f, _ := eng.ProcessFrame(p2, time.Now().Add(5*time.Millisecond))

	if f != nil && f.Reassembler != nil {
		bufStr := string(f.Reassembler.Buffer())
		t.Logf("OBSERVATION: Overlapping reassembly resolved to: %q", bufStr)
	}
}

// Test_Pillar1_Reverse_Out_Of_Order_Delivery feeds TCP segments completely in reverse order.
func Test_Pillar1_Reverse_Out_Of_Order_Delivery(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// Split HTTP GET into 3 parts:
	// Part 1: Seq 1000 (len 4): "GET "
	// Part 2: Seq 1004 (len 6): "/data "
	// Part 3: Seq 1010 (len 10): "HTTP/1.1\r\n"
	p1 := serializeTCPWithSeq(clientIP, serverIP, 50001, 80, 1000, true, false, []byte("GET "))
	p2 := serializeTCPWithSeq(clientIP, serverIP, 50001, 80, 1004, true, false, []byte("/data "))
	p3 := serializeTCPWithSeq(clientIP, serverIP, 50001, 80, 1010, true, false, []byte("HTTP/1.1\r\nHost: a.com\r\n\r\n"))

	now := time.Now()
	// Deliver in reverse order: p3, p2, p1
	_, _ = eng.ProcessFrame(p3, now)
	_, _ = eng.ProcessFrame(p2, now.Add(2*time.Millisecond))
	f, _ := eng.ProcessFrame(p1, now.Add(4*time.Millisecond))

	if f == nil || f.L7Metadata.Protocol != "HTTP" {
		t.Logf("LIMITATION DISCOVERED: When segments arrive strictly in reverse order, reassembler locks to first-seen higher sequence and discards preceding segments.")
	} else {
		t.Logf("PASS: Reverse out-of-order delivery correctly reassembled into valid HTTP stream.")
	}
}

// Test_Pillar1_DNS_Tunneling_Exfiltration_Port53 tests detection of high-entropy base64 subdomains.
func Test_Pillar1_DNS_Tunneling_Exfiltration_Port53(t *testing.T) {
	snk := &captureSink{}
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)

	clientIP := net.ParseIP("10.0.0.1")
	dnsIP := net.ParseIP("1.1.1.1")

	// Simulated base64 exfiltration chunk as subdomain
	tunnelChunk := "c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ"
	var wireQNAME []byte
	wireQNAME = append(wireQNAME, byte(len(tunnelChunk)))
	wireQNAME = append(wireQNAME, []byte(tunnelChunk)...)
	wireQNAME = append(wireQNAME, 0x07, 'e', 'v', 'i', 'l', '-', 'c', '2', 0x03, 'c', 'o', 'm', 0x00)

	dnsPkt := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dnsPkt = append(dnsPkt, wireQNAME...)
	dnsPkt = append(dnsPkt, 0x00, 0x10, 0x00, 0x01) // QTYPE=TXT (common for tunneling)

	pkt := serializeFrame(clientIP, dnsIP, 53535, 53, false, false, false, false, false, dnsPkt)
	f, _ := eng.ProcessFrame(pkt, time.Now())
	_ = eng.Close()

	if f == nil || f.L7Metadata.Protocol != "DNS" {
		t.Fatalf("failed to identify DNS on port 53")
	}

	// Check if any DNS tunneling alert fired
	var foundTunnelAlert bool
	for _, a := range snk.alerts {
		if a.Rule == "DNS_TUNNELING" {
			foundTunnelAlert = true
			break
		}
	}

	if !foundTunnelAlert {
		t.Logf("LIMITATION DISCOVERED: 58-character high-entropy DNS tunnel on port 53 extracted QNAME (%s), but no DNS_TUNNELING alert fired.", f.L7Metadata.Host)
	}
}
