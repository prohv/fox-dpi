package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func Test_CLI_Execution_E2E(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "foxdpi_cli_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	pcapPath := filepath.Join(tempDir, "input.pcap")
	if err := GenerateL7TrafficPCAP(pcapPath); err != nil {
		t.Fatalf("failed to generate pcap: %v", err)
	}

	outDir := filepath.Join(tempDir, "logs")

	// Locate binary or run with 'go run ../cmd/foxdpi'
	cmd := exec.Command("go", "run", "../cmd/foxdpi", "-f", pcapPath, "-o", outDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI command failed: %v, output: %s", err, string(out))
	}

	outputStr := string(out)
	if !strings.Contains(outputStr, "FOX-DPI RUN SUMMARY") {
		t.Errorf("expected summary table in output, got: %s", outputStr)
	}
	if !strings.Contains(outputStr, "Security Alerts Fired") {
		t.Errorf("expected alerts line in output, got: %s", outputStr)
	}

	// Verify flows.jsonl and alerts.jsonl were generated
	if _, err := os.Stat(filepath.Join(outDir, "flows.jsonl")); os.IsNotExist(err) {
		t.Errorf("flows.jsonl was not generated")
	}
	if _, err := os.Stat(filepath.Join(outDir, "alerts.jsonl")); os.IsNotExist(err) {
		t.Errorf("alerts.jsonl was not generated")
	}
}
