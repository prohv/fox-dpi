package flow

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func Test_FlowTable_BidirectionalMetrics(t *testing.T) {
	table := NewFlowTable()
	clientIP := netip.MustParseAddr("192.168.1.100")
	serverIP := netip.MustParseAddr("93.184.216.34")
	clientPort := uint16(54321)
	serverPort := uint16(80)

	t0 := time.Now()

	// Client -> Server (Request)
	key1 := NewFlowKey(clientIP, clientPort, serverIP, serverPort, 6)
	f1 := table.GetOrCreate(key1, clientIP, clientPort, 120, 0, t0)

	if f1.ClientPackets != 1 || f1.ClientBytes != 120 {
		t.Fatalf("unexpected client metrics: pkts=%d, bytes=%d", f1.ClientPackets, f1.ClientBytes)
	}

	// Server -> Client (Reply)
	key2 := NewFlowKey(serverIP, serverPort, clientIP, clientPort, 6)
	f2 := table.GetOrCreate(key2, serverIP, serverPort, 500, 0, t0.Add(10*time.Millisecond))

	if f1 != f2 {
		t.Fatalf("expected f1 and f2 to point to identical flow pointer")
	}
	if f2.ServerPackets != 1 || f2.ServerBytes != 500 {
		t.Fatalf("unexpected server metrics: pkts=%d, bytes=%d", f2.ServerPackets, f2.ServerBytes)
	}
	if table.Count() != 1 {
		t.Fatalf("expected 1 active flow, got %d", table.Count())
	}
}

func Test_FlowTable_RTT_Calculation(t *testing.T) {
	table := NewFlowTable()
	clientIP := netip.MustParseAddr("10.0.0.1")
	serverIP := netip.MustParseAddr("10.0.0.2")

	t0 := time.Now()
	key := NewFlowKey(clientIP, 12345, serverIP, 443, 6)

	// Step 1: SYN from client
	table.GetOrCreate(key, clientIP, 12345, 60, 1<<0 /* SYN */, t0)

	// Step 2: SYN-ACK from server 24ms later
	f := table.GetOrCreate(key, serverIP, 443, 60, (1<<0)|(1<<1) /* SYN+ACK */, t0.Add(24*time.Millisecond))

	if f.HandshakeRTT != 24*time.Millisecond {
		t.Fatalf("expected HandshakeRTT 24ms, got %v", f.HandshakeRTT)
	}
}

func Test_FlowTable_ConcurrentStress(t *testing.T) {
	table := NewFlowTable()
	const numGoroutines = 16
	const packetsPerWorker = 2000

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	t0 := time.Now()

	for g := 0; g < numGoroutines; g++ {
		workerID := g
		go func() {
			defer wg.Done()
			for i := 0; i < packetsPerWorker; i++ {
				srcIP := netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", workerID, i%250))
				dstIP := netip.MustParseAddr("1.1.1.1")
				key := NewFlowKey(srcIP, uint16(10000+workerID), dstIP, 443, 6)

				table.GetOrCreate(key, srcIP, uint16(10000+workerID), 64, 0, t0)
			}
		}()
	}

	wg.Wait()

	if table.Count() == 0 {
		t.Fatal("expected active flows after concurrent inserts")
	}
}

func Benchmark_FlowTable_GetOrCreate_Parallel(b *testing.B) {
	table := NewFlowTable()
	ipA := netip.MustParseAddr("192.168.1.1")
	ipB := netip.MustParseAddr("1.1.1.1")
	t0 := time.Now()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		workerPort := uint16(20000)
		for pb.Next() {
			key := NewFlowKey(ipA, workerPort, ipB, 443, 6)
			_ = table.GetOrCreate(key, ipA, workerPort, 128, 0, t0)
			workerPort++
			if workerPort > 30000 {
				workerPort = 20000
			}
		}
	})
}
