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
	"fox-dpi/internal/tui"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
)

// Version is the current release of Fox DPI.
const Version = "v0.1.4"

func main() {
	pcapFile := flag.String("f", "", "Path to PCAP file for offline analysis")
	ifaceName := flag.String("i", "", "Interface to capture live ('capture' for auto-detection, e.g. -i capture, -i Wi-Fi)")
	outputDir := flag.String("o", "output", "Directory to store flows.jsonl and alerts.jsonl")
	rotateMB := flag.Int("rotate-mb", 10, "Maximum telemetry file size in MB before gzip rotation")
	headlessFlag := flag.Bool("headless", false, "Disable interactive TUI and run in headless streaming mode")
	listIfaces := flag.Bool("list", false, "List available network interfaces and exit")
	versionFlag := flag.Bool("version", false, "Print foxdpi version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("foxdpi %s\n", Version)
		return
	}

	if *listIfaces {
		printInterfaces()
		return
	}

	if *pcapFile == "" && *ifaceName == "" {
		fmt.Printf("Fox DPI (%s) - Passive Layer 7 Deep Packet Inspection Engine\n", Version)
		fmt.Println("Usage:")
		fmt.Println("  foxdpi -i capture                   # Auto-detect active Wi-Fi/Ethernet and capture live")
		fmt.Println("  foxdpi -i <iface>                   # Capture live on specific interface (e.g. -i Wi-Fi)")
		fmt.Println("  foxdpi -f <path.pcap> [-o <out_dir>] # Replay and analyze offline PCAP")
		fmt.Println("  foxdpi -list                        # List available network interfaces")
		fmt.Println("  foxdpi -version                     # Print version and exit")
		fmt.Println()
		flag.PrintDefaults()
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

	isLive := (*ifaceName != "")
	isTTY := (isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())) &&
		(isatty.IsTerminal(os.Stdin.Fd()) || isatty.IsCygwinTerminal(os.Stdin.Fd()))
	useTUI := isLive && !*headlessFlag && isTTY

	var tuiBridge *tui.EventBridge
	var telemetrySink sink.Sink = fileSink
	if useTUI {
		tuiBridge = tui.NewEventBridge(fileSink, 512, 128)
		telemetrySink = tuiBridge
	} else if isLive {
		telemetrySink = sink.NewConsoleAlertSink(fileSink, true)
	}

	// Open Packet Source
	var src capture.PacketSource
	var captureDesc string

	if *pcapFile != "" {
		s, err := capture.OpenOffline(*pcapFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening PCAP file: %v\n", err)
			_ = telemetrySink.Close()
			os.Exit(1)
		}
		src = s
		captureDesc = fmt.Sprintf("Offline PCAP Replay (%s)", *pcapFile)
	} else {
		s, err := capture.OpenLive(*ifaceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n[!] Error starting live capture on %q:\n  %v\n\n", *ifaceName, err)
			_ = telemetrySink.Close()
			os.Exit(1)
		}
		src = s
		linkName := s.LinkType().String()
		if s.LinkType() == 101 || s.LinkType() == 228 { // LinkTypeRaw or LinkTypeIPv4
			linkName = "Raw IPv4"
		}
		if namer, ok := s.(interface{ InterfaceName() string; IP() net.IP }); ok {
			captureDesc = fmt.Sprintf("Live Capture on %s (%s) [Data Link: %s]", namer.InterfaceName(), namer.IP(), linkName)
		} else {
			captureDesc = fmt.Sprintf("Live Capture on %s [Data Link: %s]", *ifaceName, linkName)
		}
	}
	defer src.Close()

	// Initialize DPI Engine
	eng, err := engine.NewEngine(src.LinkType(), flow.DefaultEvictionConfig(), telemetrySink)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing engine: %v\n", err)
		_ = telemetrySink.Close()
		os.Exit(1)
	}

	// Cooperative Signal Handling for Graceful Shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Interrupt blocking socket read immediately upon Ctrl+C for responsive teardown
	go func() {
		<-ctx.Done()
		_ = src.Close()
	}()

	startTime := time.Now()

	if useTUI {
		model := tui.NewModel(tuiBridge, eng.Metrics, eng.ActiveFlows, captureDesc)
		prog := tea.NewProgram(model, tea.WithAltScreen())

		errCh := make(chan error, 1)
		go func() {
			errCh <- eng.Run(ctx, src)
		}()

		if _, progErr := prog.Run(); progErr != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", progErr)
		}

		stop()
		_ = src.Close()
		err = <-errCh
	} else {
		fmt.Printf("[+] Fox DPI started. Mode: %s\n", captureDesc)
		fmt.Printf("[+] Telemetry sink streaming to: %s/\n", *outputDir)
		if isLive {
			fmt.Println("[+] Press Ctrl+C to stop capture and view session summary.")
		}
		err = eng.Run(ctx, src)
	}
	elapsed := time.Since(startTime)

	// Explicitly drain active flows and flush telemetry sinks
	_ = eng.Close()

	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "[!] Engine encountered error: %v\n", err)
	}

	// Print Operational Summary
	printSummary(eng.Metrics(), elapsed, *outputDir, captureDesc)
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

func printSummary(m engine.Metrics, elapsed time.Duration, outDir, captureDesc string) {
	fmt.Print(tui.RenderSummary(m, elapsed, outDir, captureDesc))
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
