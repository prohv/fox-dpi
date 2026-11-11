package test

import (
	"net"
	"testing"
	"time"

	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"

	"github.com/google/gopacket/layers"
)

func buildDNSQueryPacket(name string) []byte {
	var wireQNAME []byte
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			part := name[start:i]
			if len(part) > 0 {
				wireQNAME = append(wireQNAME, byte(len(part)))
				wireQNAME = append(wireQNAME, []byte(part)...)
			}
			start = i + 1
		}
	}
	wireQNAME = append(wireQNAME, 0x00)

	dnsPkt := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	dnsPkt = append(dnsPkt, wireQNAME...)
	dnsPkt = append(dnsPkt, 0x00, 0x01, 0x00, 0x01) // QTYPE=A, QCLASS=IN
	return dnsPkt
}

func buildQUICInitialPacket() []byte {
	// QUIC Long Header Initial packet (RFC 9000):
	// First byte: Header Form (1) | Fixed Bit (1) | Long Packet Type (00 = Initial) | Reserved (00) | Packet Number Length (00)
	// 0b11000000 = 0xC0
	// Followed by 4-byte Version (0x00000001 for QUIC v1)
	pkt := make([]byte, 128)
	pkt[0] = 0xC0 // Long header, Initial packet
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00
	pkt[4] = 0x01 // Version 1
	pkt[5] = 0x08 // DCID len
	for i := 6; i < 14; i++ {
		pkt[i] = 0xAA
	}
	pkt[14] = 0x00 // SCID len
	// Encrypted payload follows
	for i := 15; i < len(pkt); i++ {
		pkt[i] = byte((i * 37) % 256)
	}
	return pkt
}

func Test_False_Positives_Benign_Workloads(t *testing.T) {
	snk := &captureSink{}
	eng, err := engine.NewEngine(layers.LinkTypeEthernet, flow.DefaultEvictionConfig(), snk)
	if err != nil {
		t.Fatalf("failed to init engine: %v", err)
	}
	defer eng.Close()

	clientIP := net.ParseIP("192.168.1.100")
	now := time.Now()

	// 1. Category A: 100+ Developer & SaaS Domains (TLS 443)
	devDomains := []string{
		"github.com", "api.github.com", "raw.githubusercontent.com", "gist.github.com",
		"gitlab.com", "bitbucket.org", "registry.npmjs.org", "npmjs.com", "yarnpkg.com",
		"proxy.golang.org", "pkg.go.dev", "golang.org", "pypi.org", "python.org",
		"crates.io", "static.crates.io", "registry-1.docker.io", "auth.docker.io",
		"hub.docker.com", "quay.io", "gcr.io", "ghcr.io", "aws.amazon.com",
		"s3.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com", "iam.amazonaws.com",
		"cloudformation.amazonaws.com", "console.aws.amazon.com", "googleapis.com",
		"storage.googleapis.com", "cloud.google.com", "accounts.google.com",
		"azure.com", "portal.azure.com", "management.azure.com", "dev.azure.com",
		"cloudflare.com", "api.cloudflare.com", "workers.cloudflare.com",
		"vercel.com", "vercel.app", "api.vercel.com", "supabase.com", "supabase.co",
		"datadoghq.com", "app.datadoghq.com", "sentry.io", "o12345.ingest.sentry.io",
		"postman.com", "api.postman.com", "huggingface.co", "cdn-lfs.huggingface.co",
		"grafana.com", "grafana.net", "prometheus.io", "elastic.co", "mongodb.com",
		"cloud.mongodb.com", "redis.io", "redis.com", "apache.org", "hashicorp.com",
		"registry.terraform.io", "releases.hashicorp.com", "helm.sh", "kubernetes.io",
		"stackexchange.com", "stackoverflow.com", "superuser.com", "serverfault.com",
		"askubuntu.com", "openai.com", "api.openai.com", "platform.openai.com",
		"anthropic.com", "api.anthropic.com", "linear.app", "notion.so", "api.notion.com",
		"slack.com", "api.slack.com", "discord.com", "gateway.discord.gg", "figma.com",
		"api.figma.com", "stripe.com", "api.stripe.com", "twilio.com", "api.twilio.com",
		"segment.io", "cdn.segment.com", "mixpanel.com", "amplitude.com", "launchdarkly.com",
	}

	for i, domain := range devDomains {
		serverIP := net.IPv4(100, 64, byte(i/256), byte(i%256))
		clientPort := uint16(30000 + (i % 20000))
		serverPort := uint16(443)

		// 3-way handshake + TLS ClientHello
		syn := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, true, false, false, false, nil)
		synAck := serializeFrame(serverIP, clientIP, serverPort, clientPort, true, true, true, false, false, nil)
		ack := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, false, true, false, false, nil)
		tlsPkt := serializeFrame(clientIP, serverIP, clientPort, serverPort, true, false, true, false, false, buildTestTLSClientHello(domain))

		_, _ = eng.ProcessFrame(syn, now)
		_, _ = eng.ProcessFrame(synAck, now.Add(time.Millisecond))
		_, _ = eng.ProcessFrame(ack, now.Add(2*time.Millisecond))
		_, _ = eng.ProcessFrame(tlsPkt, now.Add(3*time.Millisecond))
	}

	// 2. Developer Infrastructure Ports (TLS on 6443, 5432, 6380, 8443)
	devPorts := []struct {
		port uint16
		host string
	}{
		{6443, "kubernetes.default.svc.cluster.local"},
		{5432, "postgres.internal.dev"},
		{6380, "redis-tls.internal.dev"},
		{8443, "minikube.local"},
	}

	for i, dp := range devPorts {
		serverIP := net.ParseIP("10.96.0.1")
		clientPort := uint16(45000 + i)
		syn := serializeFrame(clientIP, serverIP, clientPort, dp.port, true, true, false, false, false, nil)
		synAck := serializeFrame(serverIP, clientIP, dp.port, clientPort, true, true, true, false, false, nil)
		ack := serializeFrame(clientIP, serverIP, clientPort, dp.port, true, false, true, false, false, nil)
		tlsPkt := serializeFrame(clientIP, serverIP, clientPort, dp.port, true, false, true, false, false, buildTestTLSClientHello(dp.host))

		_, _ = eng.ProcessFrame(syn, now)
		_, _ = eng.ProcessFrame(synAck, now.Add(time.Millisecond))
		_, _ = eng.ProcessFrame(ack, now.Add(2*time.Millisecond))
		_, _ = eng.ProcessFrame(tlsPkt, now.Add(3*time.Millisecond))
	}

	// 3. Category B: 150+ Consumer & CDN Domains (TLS 443 + long CDN labels)
	cdnDomains := []string{
		"google.com", "www.google.com", "youtube.com", "wikipedia.org", "reddit.com",
		"cloudflare.com", "fastly.com", "akamai.com", "apple.com", "icloud.com",
		"d111111abcdef8.cloudfront.net",
		"e107.dscg.akamaized.net",
		"prod-east-assets-delivery-service-01.cdn.fastly.net",
		"apple-mobile-asset-download-service-west.apple.com",
	}

	for i, domain := range cdnDomains {
		serverIP := net.IPv4(198, 51, 100, byte(i+1))
		clientPort := uint16(51000 + i)
		tlsPkt := serializeFrame(clientIP, serverIP, clientPort, 443, true, false, true, false, false, buildTestTLSClientHello(domain))
		_, _ = eng.ProcessFrame(tlsPkt, now)
	}

	// 4. QUIC on UDP 443 (Google / Cloudflare)
	quicPkt := serializeFrame(clientIP, net.ParseIP("142.250.190.46"), 52345, 443, false, false, false, false, false, buildQUICInitialPacket())
	_, _ = eng.ProcessFrame(quicPkt, now)

	// 5. Category C: LAN & OS Discovery Noise
	// Apple mDNS (UDP 5353)
	mdnsPkt := serializeFrame(clientIP, net.ParseIP("224.0.0.251"), 5353, 5353, false, false, false, false, false, buildDNSQueryPacket("_airplay._tcp.local"))
	_, _ = eng.ProcessFrame(mdnsPkt, now)

	// Windows LLMNR (UDP 5355)
	llmnrPkt := serializeFrame(clientIP, net.ParseIP("224.0.0.252"), 5355, 5355, false, false, false, false, false, buildDNSQueryPacket("WORKSTATION01"))
	_, _ = eng.ProcessFrame(llmnrPkt, now)

	// Standard DNS Query on UDP 53
	dns53Pkt := serializeFrame(clientIP, net.ParseIP("1.1.1.1"), 54321, 53, false, false, false, false, false, buildDNSQueryPacket("registry.npmjs.org"))
	_, _ = eng.ProcessFrame(dns53Pkt, now)

	// Evaluate Emitted Alerts
	if len(snk.alerts) > 0 {
		t.Logf("Total alerts emitted during benign workload: %d", len(snk.alerts))
		for idx, a := range snk.alerts {
			t.Logf("Alert [%d]: Rule=%s Severity=%s DstPort=%d Message=%s Details=%v", idx, a.Rule, a.Severity, a.DstPort, a.Message, a.Details)
		}
		t.Errorf("Expected 0 false positive alerts on benign developer/web traffic, but got %d", len(snk.alerts))
	}
}
