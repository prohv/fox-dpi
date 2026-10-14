package test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func serializeFrame(srcIP, dstIP net.IP, srcPort, dstPort uint16, isTCP bool, syn, ack, fin, rst bool, payload []byte) []byte {
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
	if !isTCP {
		ip.Protocol = layers.IPProtocolUDP
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	if isTCP {
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     syn,
			ACK:     ack,
			FIN:     fin,
			RST:     rst,
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	} else {
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		_ = udp.SetNetworkLayerForChecksum(ip)
		_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	}

	return buf.Bytes()
}

// GenerateSamplePCAP writes a deterministic 50-packet PCAP fixture for end-to-end testing.
func GenerateSamplePCAP(targetPath string) error {
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

	baseTime := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	var written int

	writePkt := func(relMs int, raw []byte) error {
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(time.Duration(relMs) * time.Millisecond),
			CaptureLength: len(raw),
			Length:        len(raw),
		}
		written++
		return w.WritePacket(ci, raw)
	}

	clientIP := net.ParseIP("192.168.1.50")
	webIP := net.ParseIP("93.184.216.34")
	dnsIP := net.ParseIP("8.8.8.8")
	tlsIP := net.ParseIP("1.1.1.1")

	// Flow 1: HTTP Conversation (10 packets)
	_ = writePkt(0, serializeFrame(clientIP, webIP, 52000, 80, true, true, false, false, false, nil))
	_ = writePkt(20, serializeFrame(webIP, clientIP, 80, 52000, true, true, true, false, false, nil))
	_ = writePkt(21, serializeFrame(clientIP, webIP, 52000, 80, true, false, true, false, false, nil))
	_ = writePkt(25, serializeFrame(clientIP, webIP, 52000, 80, true, false, true, false, false, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	_ = writePkt(45, serializeFrame(webIP, clientIP, 80, 52000, true, false, true, false, false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!")))
	_ = writePkt(48, serializeFrame(clientIP, webIP, 52000, 80, true, false, true, false, false, nil))
	_ = writePkt(50, serializeFrame(webIP, clientIP, 80, 52000, true, false, true, true, false, nil))
	_ = writePkt(51, serializeFrame(clientIP, webIP, 52000, 80, true, false, true, false, false, nil))
	_ = writePkt(52, serializeFrame(clientIP, webIP, 52000, 80, true, false, true, true, false, nil))
	_ = writePkt(53, serializeFrame(webIP, clientIP, 80, 52000, true, false, true, false, false, nil))

	// Flow 2: DNS Query & Reply (2 packets)
	_ = writePkt(5, serializeFrame(clientIP, dnsIP, 53000, 53, false, false, false, false, false, []byte("\x03www\x07example\x03com\x00")))
	_ = writePkt(15, serializeFrame(dnsIP, clientIP, 53, 53000, false, false, false, false, false, []byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01")))

	// Flow 3: TLS Session (6 packets)
	_ = writePkt(100, serializeFrame(clientIP, tlsIP, 54000, 443, true, true, false, false, false, nil))
	_ = writePkt(115, serializeFrame(tlsIP, clientIP, 443, 54000, true, true, true, false, false, nil))
	_ = writePkt(116, serializeFrame(clientIP, tlsIP, 54000, 443, true, false, true, false, false, nil))
	_ = writePkt(120, serializeFrame(clientIP, tlsIP, 54000, 443, true, false, true, false, false, []byte("\x16\x03\x01\x00\x05client_hello")))
	_ = writePkt(140, serializeFrame(tlsIP, clientIP, 443, 54000, true, false, true, false, false, []byte("\x16\x03\x03\x00\x05server_hello")))
	_ = writePkt(145, serializeFrame(clientIP, tlsIP, 54000, 443, true, false, true, false, false, nil))

	// Flows 4 to 11: 32 background packets (4 packets each across 8 distinct streams)
	for i := 0; i < 8; i++ {
		hostIP := net.ParseIP(fmt.Sprintf("10.10.0.%d", i+1))
		clientPort := uint16(60000 + i)
		_ = writePkt(200+i*10, serializeFrame(clientIP, hostIP, clientPort, 8080, true, true, false, false, false, nil))
		_ = writePkt(202+i*10, serializeFrame(hostIP, clientIP, 8080, clientPort, true, true, true, false, false, nil))
		_ = writePkt(204+i*10, serializeFrame(clientIP, hostIP, clientPort, 8080, true, false, true, false, false, []byte("DATA")))
		_ = writePkt(206+i*10, serializeFrame(hostIP, clientIP, 8080, clientPort, true, false, true, false, false, []byte("ACK_DATA")))
	}

	if written != 50 {
		return fmt.Errorf("expected 50 packets generated, wrote %d", written)
	}
	return nil
}
