//go:build darwin

package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	biocsetif      = 0x8020426c // BIOCSETIF
	biocimmediate  = 0x80044270 // BIOCIMMEDIATE
	biocsblen      = 0xc0044266 // BIOCSBLEN
)

// DarwinBPFSource captures live Ethernet frames via macOS /dev/bpf devices in pure Go.
type DarwinBPFSource struct {
	file   *os.File
	buf    []byte
	iface  string
	closed bool
}

// OpenLive initializes the platform-native packet capture source on macOS.
func OpenLive(ifaceName string) (PacketSource, error) {
	return OpenLiveDarwin(ifaceName)
}

// OpenLiveDarwin searches for an available /dev/bpf device and attaches it to the interface.
func OpenLiveDarwin(ifaceName string) (*DarwinBPFSource, error) {
	var targetIface *net.Interface

	if ifaceName == "" || ifaceName == "capture" || ifaceName == "auto" {
		var err error
		targetIface, _, err = AutoDetectInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
	} else {
		var err error
		targetIface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
		}
	}

	var file *os.File
	for i := 0; i < 256; i++ {
		path := fmt.Sprintf("/dev/bpf%d", i)
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err == nil {
			file = f
			break
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("access denied: live packet capture on macOS requires root privileges\n  -> Please run with 'sudo ./foxdpi -i capture'")
		}
	}

	if file == nil {
		return nil, fmt.Errorf("no available /dev/bpf devices found (run as root / sudo)")
	}

	fd := file.Fd()

	// Set buffer size (64 KB)
	bufLen := uint32(65536)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, biocsblen, uintptr(unsafe.Pointer(&bufLen)))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("ioctl BIOCSBLEN: %w", errno)
	}

	// Set interface (BIOCSETIF)
	type ifreq struct {
		name [16]byte
		pad  [16]byte
	}
	var ifr ifreq
	copy(ifr.name[:], targetIface.Name)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, biocsetif, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("ioctl BIOCSETIF on %s: %w", targetIface.Name, errno)
	}

	// Enable immediate mode (BIOCIMMEDIATE)
	enable := uint32(1)
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, biocimmediate, uintptr(unsafe.Pointer(&enable)))
	if errno != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("ioctl BIOCIMMEDIATE: %w", errno)
	}

	return &DarwinBPFSource{
		file:  file,
		buf:   make([]byte, 65536),
		iface: targetIface.Name,
	}, nil
}

// ReadPacket reads from the macOS BPF descriptor and strips the BPF header.
func (s *DarwinBPFSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	n, err := s.file.Read(s.buf)
	if err != nil {
		if s.closed {
			return nil, gopacket.CaptureInfo{}, fmt.Errorf("bpf device closed")
		}
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("read bpf: %w", err)
	}

	// BPF packet header is 18-20 bytes (bpf_hdr structure)
	// bh_hdrlen indicates offset to raw packet bytes
	if n < 18 {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("truncated bpf frame (%d bytes)", n)
	}

	hdrLen := int(s.buf[16]) | int(s.buf[17])<<8
	if hdrLen >= n || hdrLen < 18 {
		hdrLen = 18
	}

	data := s.buf[hdrLen:n]
	ts := time.Now()
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: len(data),
		Length:        len(data),
	}

	return data, ci, nil
}

// LinkType returns LinkTypeEthernet for macOS BPF Ethernet devices.
func (s *DarwinBPFSource) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// InterfaceName returns the active interface name.
func (s *DarwinBPFSource) InterfaceName() string {
	return s.iface
}

// Close releases the BPF device handle.
func (s *DarwinBPFSource) Close() error {
	s.closed = true
	return s.file.Close()
}
