package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fox-dpi/internal/capture"
	"fox-dpi/internal/engine"
	"fox-dpi/internal/flow"
	"fox-dpi/internal/sink"
)

func main() {
	pcapFile := flag.String("f", "", "Path to PCAP file for offline analysis")
	ifaceName := flag.String("i", "", "Network interface name for packet capture")
	outputDir := flag.String("o", "output", "Directory to store flows.jsonl and alerts.jsonl")
	rotateMB := flag.Int("rotate-mb", 10, "Maximum telemetry file size in MB before gzip rotation")
	listIfaces := flag.Bool("list", false, "List available network interfaces and exit")

	flag.Parse()

	if *listIfaces {
		printInterfaces()
		return
	}

	if *pcapFile == "" && *ifaceName == "" {
		fmt.Println("Fox DPI - Passive Layer 7 Deep Packet Inspection Engine")
		fmt.Println("Usage:")
		fmt.Println("  foxdpi -f <path.pcap> [-o <out_dir>] [-rotate-mb <mb>]")
		fmt.Println("  foxdpi -list")
		fmt.Println()
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *ifaceName != "" && *pcapFile == "" {
		fmt.Fprintf(os.Stderr, "Live interface capture (-i %s) requires platform-native packet drivers.\n", *ifaceName)
		fmt.Fprintf(os.Stderr, "Please specify an offline PCAP file (-f <file.pcap>) for analysis.\n")
		os.Exit(1)
	}

	// Initialize Telemetry Sink
	sinkCfg := sink.DefaultFileSinkConfig(*outputDir)
	if *rotateMB > 0 {
		sinkCfg.MaxSizeBytes = int64(*rotateMB) * 1024 * 1024
	}
	fileSink, err := sink.NewFileSink(sinkCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing telemetry sink: %v\n", err)
		os.Exit(1)
	}

	// Open Packet Source
	src, err := capture.OpenOffline(*pcapFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening PCAP file: %v\n", err)
		_ = fileSink.Close()
		os.Exit(1)
	}
	defer src.Close()

	// Initialize DPI Engine
	eng, err := engine.NewEngine(src.LinkType(), flow.DefaultEvictionConfig(), fileSink)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing engine: %v\n", err)
		_ = fileSink.Close()
		os.Exit(1)
	}

	// Cooperative Signal Handling for Graceful Shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startTime := time.Now()
	fmt.Printf("[+] Fox DPI started. Analyzing: %s\n", *pcapFile)
	fmt.Printf("[+] Telemetry sink streaming to: %s/\n", *outputDir)

	err = eng.Run(ctx, src)
	elapsed := time.Since(startTime)

	// Explicitly drain active flows and flush telemetry sinks
	_ = eng.Close()

	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "[!] Engine encountered error: %v\n", err)
	}

	// Print Operational Summary
	printSummary(eng.Metrics(), elapsed, *outputDir)
}

func printInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing network interfaces: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Available Network Interfaces:")
	fmt.Println("--------------------------------------------------------------------------------")
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var addrStrs []string
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		mac := iface.HardwareAddr.String()
		if mac == "" {
			mac = "none"
		}
		fmt.Printf(" [%2d] %-20s MTU: %-5d MAC: %-17s IPs: %s\n",
			iface.Index, iface.Name, iface.MTU, mac, strings.Join(addrStrs, ", "))
	}
	fmt.Println("--------------------------------------------------------------------------------")
}

func printSummary(m engine.Metrics, elapsed time.Duration, outDir string) {
	secs := elapsed.Seconds()
	rate := float64(0)
	if secs > 0 {
		rate = float64(m.TotalPackets) / secs
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("          FOX-DPI RUN SUMMARY           ")
	fmt.Println("========================================")
	fmt.Printf(" Total Packets Processed : %s\n", formatNumber(m.TotalPackets))
	fmt.Printf(" Total Volume Captured   : %s\n", formatBytes(m.TotalBytes))
	fmt.Printf(" Packet Loss / Errors    : %s\n", formatNumber(m.DropPackets))
	fmt.Println("----------------------------------------")
	fmt.Printf(" Flows Emitted to Sink   : %s\n", formatNumber(m.EmittedFlows))
	fmt.Printf(" Active Flows at Exit    : %s\n", formatNumber(uint64(m.ActiveFlows)))
	fmt.Printf(" Security Alerts Fired   : %s\n", formatNumber(m.EmittedAlerts))
	fmt.Printf(" Dropped Sink Events     : %s\n", formatNumber(m.DroppedFlows+m.DroppedAlerts))
	fmt.Println("----------------------------------------")
	fmt.Printf(" Telemetry Output Dir    : %s/\n", outDir)
	fmt.Printf(" Elapsed Run Time        : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf(" Processing Throughput   : %s pkts/sec\n", formatNumber(uint64(rate)))
	fmt.Println("========================================")
}

func formatNumber(n uint64) string {
	in := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(in)+(len(in)-1)/3)
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
