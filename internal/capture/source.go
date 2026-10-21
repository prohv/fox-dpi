package capture

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PacketSource abstracts live interfaces and offline capture files.
type PacketSource interface {
	ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error)
	LinkType() layers.LinkType
	Close() error
}

// FileSource reads standard PCAP files using pure Go without requiring cgo drivers.
type FileSource struct {
	file   *os.File
	reader *pcapgo.Reader
}

// OpenOffline opens a .pcap file for reading.
func OpenOffline(path string) (*FileSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("read pcap header: %w", err)
	}

	return &FileSource{
		file:   f,
		reader: r,
	}, nil
}

// ReadPacket returns the next raw packet frame and capture metadata.
func (s *FileSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	data, ci, err := s.reader.ReadPacketData()
	if err != nil {
		if err == io.EOF {
			return nil, ci, io.EOF
		}
		return nil, ci, fmt.Errorf("read packet: %w", err)
	}
	return data, ci, nil
}

// LinkType returns the data link type (e.g. Ethernet, Loopback).
func (s *FileSource) LinkType() layers.LinkType {
	return s.reader.LinkType()
}

// Close releases the underlying file handle.
func (s *FileSource) Close() error {
	return s.file.Close()
}

// AutoDetectInterface finds the primary active network adapter with a valid routable IPv4 address.
// It prioritizes active Wi-Fi adapters, falling back to active Ethernet or other adapters.
func AutoDetectInterface() (*net.Interface, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("list interfaces: %w", err)
	}

	var bestIface *net.Interface
	var bestIP net.IP

	for i := range ifaces {
		iface := &ifaces[i]
		// Skip down and loopback interfaces
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			ip4 := ipNet.IP.To4()
			// Skip link-local addresses (169.254.x.x) if possible
			if ip4.IsLinkLocalUnicast() {
				continue
			}

			// If interface name contains Wi-Fi / WLAN / Wireless, prioritize it immediately
			nameLower := strings.ToLower(iface.Name)
			if strings.Contains(nameLower, "wi-fi") || strings.Contains(nameLower, "wifi") ||
				strings.Contains(nameLower, "wlan") || strings.Contains(nameLower, "wireless") {
				return iface, ip4, nil
			}

			if bestIface == nil {
				bestIface = iface
				bestIP = ip4
			}
		}
	}

	if bestIface != nil {
		return bestIface, bestIP, nil
	}

	return nil, nil, fmt.Errorf("no active internet-facing network adapter found")
}
