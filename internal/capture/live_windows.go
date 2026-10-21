//go:build windows

package capture

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	sioRcvAll = 0x98000001
	rcvAllOn  = 1
)

// WindowsRawSocketSource captures live IPv4 frames via Winsock2 SIO_RCVALL in pure Go.
type WindowsRawSocketSource struct {
	fd     syscall.Handle
	buf    []byte
	iface  string
	ip     net.IP
	closed bool
}

// OpenLive initializes the platform-native packet capture source on Windows.
func OpenLive(ifaceName string) (PacketSource, error) {
	return OpenLiveWindows(ifaceName)
}

// OpenLiveWindows opens a native Windows raw socket bound to the interface IP.
func OpenLiveWindows(ifaceName string) (*WindowsRawSocketSource, error) {
	var targetIface *net.Interface
	var targetIP net.IP

	if ifaceName == "" || ifaceName == "capture" || ifaceName == "auto" {
		var err error
		targetIface, targetIP, err = AutoDetectInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
	} else {
		var err error
		targetIface, err = net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
		}
		addrs, err := targetIface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("get addresses for interface %q: %w", ifaceName, err)
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
				targetIP = ipNet.IP.To4()
				break
			}
		}
		if targetIP == nil {
			return nil, fmt.Errorf("interface %q has no valid IPv4 address assigned", ifaceName)
		}
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		if errors.Is(err, syscall.WSAEACCES) || errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("access denied: live packet capture on Windows requires Administrator privileges\n  -> Please right-click terminal and select 'Run as Administrator'")
		}
		return nil, fmt.Errorf("create raw socket: %w", err)
	}

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], targetIP)
	sa.Port = 0

	if err := syscall.Bind(fd, &sa); err != nil {
		_ = syscall.Closesocket(fd)
		return nil, fmt.Errorf("bind raw socket to %s (%s): %w", targetIface.Name, targetIP, err)
	}

	inBuf := uint32(rcvAllOn)
	var outBuf uint32
	var retBytes uint32

	err = syscall.WSAIoctl(
		fd,
		sioRcvAll,
		(*byte)(unsafe.Pointer(&inBuf)),
		uint32(unsafe.Sizeof(inBuf)),
		(*byte)(unsafe.Pointer(&outBuf)),
		uint32(unsafe.Sizeof(outBuf)),
		&retBytes,
		nil,
		0,
	)
	if err != nil {
		_ = syscall.Closesocket(fd)
		return nil, fmt.Errorf("enable promiscuous SIO_RCVALL on %s: %w", targetIface.Name, err)
	}

	return &WindowsRawSocketSource{
		fd:    fd,
		buf:   make([]byte, 65536),
		iface: targetIface.Name,
		ip:    targetIP,
	}, nil
}

// ReadPacket polls the next raw IP packet from the Winsock raw socket.
func (s *WindowsRawSocketSource) ReadPacket() ([]byte, gopacket.CaptureInfo, error) {
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

// LinkType returns LinkTypeIPv4 because Windows raw sockets deliver Layer 3 IP datagrams.
func (s *WindowsRawSocketSource) LinkType() layers.LinkType {
	return layers.LinkTypeIPv4
}

// InterfaceName returns the name of the active capture adapter.
func (s *WindowsRawSocketSource) InterfaceName() string {
	return s.iface
}

// IP returns the bound IP address of the adapter.
func (s *WindowsRawSocketSource) IP() net.IP {
	return s.ip
}

// Close releases the underlying Windows socket handle.
func (s *WindowsRawSocketSource) Close() error {
	s.closed = true
	return syscall.Closesocket(s.fd)
}
