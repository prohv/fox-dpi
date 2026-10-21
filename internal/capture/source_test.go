package capture

import (
	"testing"
)

func Test_AutoDetectInterface(t *testing.T) {
	iface, ip, err := AutoDetectInterface()
	if err != nil {
		t.Logf("AutoDetectInterface returned error (no active interface?): %v", err)
		return
	}

	if iface == nil || ip == nil {
		t.Fatalf("expected valid interface and IP, got: iface=%v, ip=%v", iface, ip)
	}

	if ip.To4() == nil {
		t.Errorf("expected IPv4 address, got: %v", ip)
	}

	t.Logf("PASS: Auto-detected primary active interface: %s (IP: %s)", iface.Name, ip)
}
