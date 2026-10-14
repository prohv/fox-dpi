package test

import (
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// GenerateL7TrafficPCAP creates a rich capture containing fragmented TLS, HTTP keep-alive, DNS, and non-standard port traffic.
func GenerateL7TrafficPCAP(targetPath string) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return err
	}

	f, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	baseTime := time.Date(2026, 10, 14, 15, 0, 0, 0, time.UTC)

	writePkt := func(relMs int, raw []byte) error {
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(relMs) * time.Millisecond),
			CaptureLength: len(raw),
			Length:        len(raw),
		}
		return w.WritePacket(ci, raw)
	}

	clientIP := net.ParseIP("192.168.1.50")
	dnsIP := net.ParseIP("1.1.1.1")
	githubIP := net.ParseIP("140.82.121.4")
	webIP := net.ParseIP("93.184.216.34")
	spoofIP := net.ParseIP("198.51.100.1")

	// 1. DNS UDP Query for api.github.com
	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'a', 'p', 'i', 0x06, 'g', 'i', 't', 'h', 'u', 'b', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	_ = writePkt(0, serializeFrame(clientIP, dnsIP, 53000, 53, false, false, false, false, false, dnsQuery))

	// 2. TLS ClientHello FRAGMENTED across two TCP segments (SNI: api.github.com)
	tlsFull := buildTestTLSClientHello("api.github.com")
	splitPoint := 40
	tlsPart1 := tlsFull[:splitPoint]
	tlsPart2 := tlsFull[splitPoint:]

	// SYN -> SYN-ACK -> ACK
	_ = writePkt(10, serializeFrame(clientIP, githubIP, 54000, 443, true, true, false, false, false, nil))
	_ = writePkt(25, serializeFrame(githubIP, clientIP, 443, 54000, true, true, true, false, false, nil))
	_ = writePkt(26, serializeFrame(clientIP, githubIP, 54000, 443, true, false, true, false, false, nil))
	// Fragment 1
	_ = writePkt(30, serializeTCPWithSeq(clientIP, githubIP, 54000, 443, 1000, true, false, tlsPart1))
	// Fragment 2 (completes ClientHello)
	_ = writePkt(35, serializeTCPWithSeq(clientIP, githubIP, 54000, 443, 1000+uint32(splitPoint), true, false, tlsPart2))
	// Post-handshake encrypted Application Data (testing L7 bypass)
	_ = writePkt(50, serializeTCPWithSeq(clientIP, githubIP, 54000, 443, 1500, true, false, []byte{0x17, 0x03, 0x03, 0x00, 0x20, 0xAA, 0xBB}))

	// 3. HTTP/1.1 Keep-Alive Session (Request 1, then Request 2 on same port 52000)
	_ = writePkt(60, serializeFrame(clientIP, webIP, 52000, 80, true, true, false, false, false, nil))
	_ = writePkt(70, serializeFrame(webIP, clientIP, 80, 52000, true, true, true, false, false, nil))
	httpReq1 := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n")
	_ = writePkt(72, serializeTCPWithSeq(clientIP, webIP, 52000, 80, 2000, true, false, httpReq1))
	// Request 2 on same connection (smuggling / keep-alive test)
	httpReq2 := []byte("POST /api/telemetry HTTP/1.1\r\nHost: telemetry.service.internal\r\nUser-Agent: curl/8.0\r\n\r\n")
	_ = writePkt(90, serializeTCPWithSeq(clientIP, webIP, 52000, 80, 2000+uint32(len(httpReq1)), true, false, httpReq2))

	// 4. Port Spoofing / Evasion: TLS on port 8080 (SNI: evasion-test.cloudflare.com)
	tlsSpoofed := buildTestTLSClientHello("evasion-test.cloudflare.com")
	_ = writePkt(100, serializeFrame(clientIP, spoofIP, 55000, 8080, true, true, false, false, false, nil))
	_ = writePkt(110, serializeTCPWithSeq(clientIP, spoofIP, 55000, 8080, 3000, true, false, tlsSpoofed))

	// 5. Port Spoofing: HTTP on high port 54321 (Host: custom-proxy.net)
	httpSpoofed := []byte("GET /proxy HTTP/1.1\r\nHost: custom-proxy.net\r\n\r\n")
	_ = writePkt(120, serializeFrame(clientIP, spoofIP, 56000, 54321, true, true, false, false, false, nil))
	_ = writePkt(130, serializeTCPWithSeq(clientIP, spoofIP, 56000, 54321, 4000, true, false, httpSpoofed))

	return nil
}

func serializeTCPWithSeq(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, ack, fin bool, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		ACK:     ack,
		FIN:     fin,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildTestTLSClientHello(serverName string) []byte {
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x04, 0xc0, 0x2f, 0xc0, 0x30)
	body = append(body, 0x01, 0x00)

	sniPayload := []byte{
		0x00, byte(len(serverName) + 3),
		0x00,
		byte(len(serverName) >> 8), byte(len(serverName)),
	}
	sniPayload = append(sniPayload, []byte(serverName)...)

	var extBuf []byte
	extBuf = append(extBuf, 0x00, 0x00)
	extBuf = append(extBuf, byte(len(sniPayload)>>8), byte(len(sniPayload)))
	extBuf = append(extBuf, sniPayload...)

	body = append(body, byte(len(extBuf)>>8), byte(len(extBuf)))
	body = append(body, extBuf...)

	handshake := []byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record
}
