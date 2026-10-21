//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// LinuxPacketSource captures live Layer 2 Ethernet frames via native AF_PACKET raw sockets in pure Go.
type LinuxPacketSource struct {
	fd     int
	buf    []byte
	iface  string
	closed bool
}

// OpenLive initializes the platform-native packet capture source on Linux.
func OpenLive(ifaceName string) (PacketSource, error) {
	return OpenLiveLinux(ifaceName)
}

// OpenLiveLinux creates an AF_PACKET socket bound to the specified network interface.
func OpenLiveLinux(ifaceName string) (*LinuxPacketSource, error) {
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

	// ETH_P_ALL in network byte order (0x0003 -> 0x0300)
	proto := int(htons(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("access denied: live packet capture on Linux requires root privileges\n  -> Please run with 'sudo ./foxdpi -i capture' or assign capabilities: 'sudo setcap cap_net_raw=eip ./foxdpi'")
		}
		return nil, fmt.Errorf("create AF_PACKET socket: %w", err)
	}

	sll := syscall.SockaddrLinklayer{
		Protocol: uint16(proto),
		Ifindex:  targetIface.Index,
	}

	if err := syscall.Bind(fd, &sll); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind AF_PACKET socket to %s (index %d): %w", targetIface.Name, targetIface.Index, err)
	}

	return &LinuxPacketSource{
		fd:    fd,
		buf:   make([]byte, 65536),
		iface: targetIface.Name,
	}, nil
}

// ReadPacket reads the next raw Layer 2 frame from the AF_PACKET socket.
func (s *LinuxPacketSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
	n, _, err := syscall.Recvfrom(s.fd, s.buf, 0)
	if err != nil {
		if s.closed {
			return nil, gopacket.CaptureInfo{}, fmt.Errorf("socket closed")
		}
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("recvfrom: %w", err)
	}

	ts := time.Now()
	ci := gopacket.CaptureInfo{
		Timestamp:     ts,
		CaptureLength: n,
		Length:        n,
	}

	return s.buf[:n], ci, nil
}

// LinkType returns LinkTypeEthernet for AF_PACKET raw sockets.
func (s *LinuxPacketSource) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// InterfaceName returns the active interface name.
func (s *LinuxPacketSource) InterfaceName() string {
	return s.iface
}

// Close releases the socket file descriptor.
func (s *LinuxPacketSource) Close() error {
	s.closed = true
	return syscall.Close(s.fd)
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | (i>>8)&0x00ff
}
