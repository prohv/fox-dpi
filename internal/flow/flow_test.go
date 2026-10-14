package flow

import (
	"net/netip"
	"testing"
	"time"

	"fox-dpi/internal/protocol"
	"fox-dpi/internal/reassembly"
)

func Test_Flow_L7Lifecycle_TLS_Bypass(t *testing.T) {
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("1.1.1.1")
	key := NewFlowKey(ip1, 50000, ip2, 443, 6)

	f := NewFlow(key, ip1, 50000, 60, 0, time.Now())
	f.Reassembler = reassembly.NewStreamReassembler(1000)
	f.Reassembler.Push(1000, []byte("TLS_HANDSHAKE"))

	meta := protocol.Metadata{
		Protocol: "TLS",
		Host:     "cloudflare.com",
	}
	f.SetL7Metadata(meta)

	if !f.L7Identified {
		t.Fatal("expected flow to be marked identified")
	}
	if !f.L7Bypass {
		t.Fatal("expected TLS flow to enable L7Bypass for encrypted traffic")
	}
	if f.Reassembler != nil {
		t.Fatalf("expected reassembler to be returned to pool after TLS match, got non-nil")
	}
}

func Test_Flow_L7Lifecycle_HTTP_KeepAlive(t *testing.T) {
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("93.184.216.34")
	key := NewFlowKey(ip1, 52000, ip2, 80, 6)

	f := NewFlow(key, ip1, 52000, 100, 0, time.Now())
	f.Reassembler = reassembly.NewStreamReassembler(1000)
	f.Reassembler.Push(1000, []byte("GET / HTTP/1.1\r\n\r\n"))

	meta := protocol.Metadata{
		Protocol: "HTTP",
		Host:     "example.com",
	}
	f.SetL7Metadata(meta)

	if !f.L7Identified {
		t.Fatal("expected flow to be marked identified")
	}
	if f.L7Bypass {
		t.Fatal("expected HTTP flow to keep L7Bypass disabled for keep-alive request inspection")
	}
	if f.Reassembler == nil {
		t.Fatal("expected reassembler to be reset ready for next HTTP request")
	}
}
