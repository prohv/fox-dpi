package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, syn, ack, fin, rst bool, payload []byte) []byte {
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
		SYN:     syn,
		ACK:     ack,
		FIN:     fin,
		RST:     rst,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
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
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func Test_Decapsulator_IPv4_TCP(t *testing.T) {
	d, err := NewDecapsulator(layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("failed to create decapsulator: %v", err)
	}

	raw := buildTCPPacket(
		net.ParseIP("192.168.1.10"),
		net.ParseIP("93.184.216.34"),
		54321, 80,
		true, false, false, false,
		[]byte("GET / HTTP/1.1\r\n\r\n"),
	)

	pkt, err := d.Decode(raw)
	if err != nil {
		t.Fatalf("unexpected error decoding tcp packet: %v", err)
	}

	if pkt.SrcIP.String() != "192.168.1.10" || pkt.DstIP.String() != "93.184.216.34" {
		t.Fatalf("unexpected IPs: %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.SrcPort != 54321 || pkt.DstPort != 80 {
		t.Fatalf("unexpected ports: %d -> %d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.Proto != 6 {
		t.Fatalf("expected proto 6, got %d", pkt.Proto)
	}
	if pkt.TCPFlags&FlagSYN == 0 {
		t.Fatal("expected SYN flag to be set")
	}
	if string(pkt.Payload) != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("unexpected payload: %s", string(pkt.Payload))
	}
}

func Test_Decapsulator_IPv4_UDP(t *testing.T) {
	d, err := NewDecapsulator(layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("failed to create decapsulator: %v", err)
	}

	raw := buildUDPPacket(
		net.ParseIP("10.0.0.5"),
		net.ParseIP("8.8.8.8"),
		41234, 53,
		[]byte("DNS_QUERY"),
	)

	pkt, err := d.Decode(raw)
	if err != nil {
		t.Fatalf("unexpected error decoding udp packet: %v", err)
	}

	if pkt.SrcIP.String() != "10.0.0.5" || pkt.DstIP.String() != "8.8.8.8" {
		t.Fatalf("unexpected IPs: %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.SrcPort != 41234 || pkt.DstPort != 53 {
		t.Fatalf("unexpected ports: %d -> %d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.Proto != 17 {
		t.Fatalf("expected proto 17, got %d", pkt.Proto)
	}
	if string(pkt.Payload) != "DNS_QUERY" {
		t.Fatalf("unexpected payload: %s", string(pkt.Payload))
	}
}

func Test_Decapsulator_MalformedAndTruncated_NoPanic(t *testing.T) {
	d, err := NewDecapsulator(layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("failed to create decapsulator: %v", err)
	}

	cases := [][]byte{
		{},
		{0x01, 0x02, 0x03},
		make([]byte, 14), // truncated ethernet only
		make([]byte, 20), // truncated IP
		make([]byte, 40), // corrupted headers
	}

	for i, c := range cases {
		_, decodeErr := d.Decode(c)
		if decodeErr == nil && len(c) < 34 {
			t.Fatalf("case %d: expected error on truncated packet, got nil", i)
		}
	}
}

func Test_Decapsulator_Raw_IPv4(t *testing.T) {
	d, err := NewDecapsulator(layers.LinkTypeIPv4)
	if err != nil {
		t.Fatalf("failed to create IPv4 decapsulator: %v", err)
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    net.ParseIP("10.0.0.5"),
		DstIP:    net.ParseIP("1.1.1.1"),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(45000),
		DstPort: layers.TCPPort(443),
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload([]byte("HELLO_RAW_IP")))

	rawIPv4 := buf.Bytes()

	pkt, err := d.Decode(rawIPv4)
	if err != nil {
		t.Fatalf("unexpected error decoding raw IPv4: %v", err)
	}

	if pkt.SrcIP.String() != "10.0.0.5" || pkt.DstIP.String() != "1.1.1.1" {
		t.Fatalf("unexpected IPs: %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.SrcPort != 45000 || pkt.DstPort != 443 {
		t.Fatalf("unexpected ports: %d -> %d", pkt.SrcPort, pkt.DstPort)
	}
	if pkt.Proto != 6 {
		t.Fatalf("expected Proto 6, got %d", pkt.Proto)
	}
	if string(pkt.Payload) != "HELLO_RAW_IP" {
		t.Fatalf("unexpected payload: %s", string(pkt.Payload))
	}
}

func Benchmark_Decapsulate(b *testing.B) {
	d, _ := NewDecapsulator(layers.LinkTypeEthernet)
	raw := buildTCPPacket(
		net.ParseIP("192.168.1.10"),
		net.ParseIP("93.184.216.34"),
		54321, 443,
		false, true, false, false,
		[]byte("TLS_CLIENT_HELLO"),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = d.Decode(raw)
	}
}
