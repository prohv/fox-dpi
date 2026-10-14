package capture

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	FlagSYN uint8 = 1 << 0
	FlagACK uint8 = 1 << 1
	FlagFIN uint8 = 1 << 2
	FlagRST uint8 = 1 << 3
)

// DecodedPacket holds zero-heap extracted headers from a single wire frame.
type DecodedPacket struct {
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Proto    uint8
	TCPFlags uint8
	Payload  []byte
	Length   int
}

// Decapsulator walks network headers in-place reusing pre-allocated layer structs.
type Decapsulator struct {
	eth     layers.Ethernet
	loop    layers.Loopback
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
	output  DecodedPacket
}

// NewDecapsulator sets up zero-alloc layer decoders for the specified data link type.
func NewDecapsulator(linkType layers.LinkType) (*Decapsulator, error) {
	d := &Decapsulator{
		decoded: make([]gopacket.LayerType, 0, 8),
	}

	var firstLayer gopacket.DecodingLayer
	var firstType gopacket.LayerType

	switch linkType {
	case layers.LinkTypeEthernet:
		firstLayer = &d.eth
		firstType = layers.LayerTypeEthernet
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		firstLayer = &d.loop
		firstType = layers.LayerTypeLoopback
	default:
		// Default to Ethernet fallback
		firstLayer = &d.eth
		firstType = layers.LayerTypeEthernet
	}

	d.parser = gopacket.NewDecodingLayerParser(
		firstType,
		firstLayer,
		&d.ip4,
		&d.ip6,
		&d.tcp,
		&d.udp,
	)
	d.parser.IgnoreUnsupported = true

	return d, nil
}

// Decode extracts transport and network fields from raw packet bytes.
func (d *Decapsulator) Decode(data []byte) (*DecodedPacket, error) {
	if len(data) == 0 {
		return nil, errors.New("empty packet data")
	}

	d.decoded = d.decoded[:0]
	d.output = DecodedPacket{
		Length: len(data),
	}

	err := d.parser.DecodeLayers(data, &d.decoded)
	if err != nil && len(d.decoded) == 0 {
		return nil, fmt.Errorf("decapsulate packet: %w", err)
	}

	hasNetwork := false
	hasTransport := false

	// Extract layers in order
	for _, typ := range d.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			src, ok1 := netip.AddrFromSlice(d.ip4.SrcIP)
			dst, ok2 := netip.AddrFromSlice(d.ip4.DstIP)
			if ok1 && ok2 {
				d.output.SrcIP = src.Unmap()
				d.output.DstIP = dst.Unmap()
				d.output.Proto = uint8(d.ip4.Protocol)
				hasNetwork = true
			}
		case layers.LayerTypeIPv6:
			src, ok1 := netip.AddrFromSlice(d.ip6.SrcIP)
			dst, ok2 := netip.AddrFromSlice(d.ip6.DstIP)
			if ok1 && ok2 {
				d.output.SrcIP = src.Unmap()
				d.output.DstIP = dst.Unmap()
				d.output.Proto = uint8(d.ip6.NextHeader)
				hasNetwork = true
			}
		case layers.LayerTypeTCP:
			d.output.SrcPort = uint16(d.tcp.SrcPort)
			d.output.DstPort = uint16(d.tcp.DstPort)
			d.output.Payload = d.tcp.Payload
			d.output.TCPFlags = 0
			if d.tcp.SYN {
				d.output.TCPFlags |= FlagSYN
			}
			if d.tcp.ACK {
				d.output.TCPFlags |= FlagACK
			}
			if d.tcp.FIN {
				d.output.TCPFlags |= FlagFIN
			}
			if d.tcp.RST {
				d.output.TCPFlags |= FlagRST
			}
			hasTransport = true
		case layers.LayerTypeUDP:
			d.output.SrcPort = uint16(d.udp.SrcPort)
			d.output.DstPort = uint16(d.udp.DstPort)
			d.output.Payload = d.udp.Payload
			hasTransport = true
		}
	}

	if !hasNetwork || !hasTransport {
		return nil, errors.New("packet missing network or transport layer")
	}

	return &d.output, nil
}
