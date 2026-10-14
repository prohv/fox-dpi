package capture

import (
	"fmt"
	"io"
	"os"

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
