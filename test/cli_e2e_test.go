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

func Test_CLI_Help_E2E(t *testing.T) {
	cmd := exec.Command("go", "run", "../cmd/foxdpi")
	out, err := cmd.CombinedOutput()
	// Exits with code 1 on empty args
	if err == nil {
		t.Errorf("expected error exit code when no flags passed")
	}
	outputStr := string(out)
	if !strings.Contains(outputStr, "foxdpi -i capture") {
		t.Errorf("expected usage to contain 'foxdpi -i capture', got: %s", outputStr)
	}
}

func Test_CLI_ListInterfaces_E2E(t *testing.T) {
	cmd := exec.Command("go", "run", "../cmd/foxdpi", "-list")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI -list failed: %v, output: %s", err, string(out))
	}
	outputStr := string(out)
	if !strings.Contains(outputStr, "Available Network Interfaces:") {
		t.Errorf("expected interface list table in output, got: %s", outputStr)
	}
}

func Test_CLI_InvalidInterface_E2E(t *testing.T) {
	cmd := exec.Command("go", "run", "../cmd/foxdpi", "-i", "nonexistent_iface_9999")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for non-existent interface")
	}
	outputStr := string(out)
	if !strings.Contains(outputStr, "Error starting live capture") {
		t.Errorf("expected capture error message, got: %s", outputStr)
	}
}

func Test_CLI_Version_E2E(t *testing.T) {
	cmd := exec.Command("go", "run", "../cmd/foxdpi", "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI -version failed: %v, output: %s", err, string(out))
	}
	outputStr := string(out)
	if !strings.Contains(outputStr, "foxdpi v0.1.1") {
		t.Errorf("expected version output 'foxdpi v0.1.1', got: %s", outputStr)
	}
}
