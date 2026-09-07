package benchmark_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/bashmyhed/ulpf/internal/benchmark"
	"github.com/bashmyhed/ulpf/internal/generator"
)

// Test benchmark tier 1 (10K events)
func TestBenchmarkTier1(t *testing.T) {
	config := benchmark.Config{
		Tier:       1,
		Events:     10000,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
	}

	result, err := benchmark.Run(config)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	if result.EventsProcessed != 10000 {
		t.Errorf("expected 10000 events, got %d", result.EventsProcessed)
	}

	if result.EventsPerSecond < 1000 {
		t.Errorf("expected at least 1000 events/sec, got %f", result.EventsPerSecond)
	}

	t.Logf("Tier 1: %d events in %v (%.0f events/sec)", result.EventsProcessed, result.Duration, result.EventsPerSecond)
}

// Test benchmark tier 2 (100K events)
func TestBenchmarkTier2(t *testing.T) {
	config := benchmark.Config{
		Tier:       2,
		Events:     100000,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
	}

	result, err := benchmark.Run(config)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	if result.EventsProcessed != 100000 {
		t.Errorf("expected 100000 events, got %d", result.EventsProcessed)
	}

	t.Logf("Tier 2: %d events in %v (%.0f events/sec)", result.EventsProcessed, result.Duration, result.EventsPerSecond)
}

// Test benchmark with different formats
func TestBenchmarkFormats(t *testing.T) {
	formats := []string{"json", "syslog", "keyvalue", "apache"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			config := benchmark.Config{
				Tier:       1,
				Events:     1000,
				Format:     format,
				SourceID:   "test",
				Seed:       42,
			}

			result, err := benchmark.Run(config)
			if err != nil {
				t.Fatalf("benchmark failed for format %s: %v", format, err)
			}

			if result.EventsProcessed != 1000 {
				t.Errorf("expected 1000 events, got %d", result.EventsProcessed)
			}
		})
	}
}

// Test benchmark metrics collection
func TestBenchmarkMetrics(t *testing.T) {
	config := benchmark.Config{
		Tier:       1,
		Events:     1000,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
	}

	result, err := benchmark.Run(config)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	if result.BytesProcessed == 0 {
		t.Error("expected bytes_processed > 0")
	}

	if result.Duration == 0 {
		t.Error("expected duration > 0")
	}

	if result.ErrorRate != 0 {
		t.Errorf("expected error_rate=0, got %f", result.ErrorRate)
	}
}

// Test benchmark with large events
func TestBenchmarkLargeEvents(t *testing.T) {
	config := benchmark.Config{
		Tier:       1,
		Events:     100,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
		EventSize:  65536, // 64KB events
	}

	result, err := benchmark.Run(config)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	if result.EventsProcessed != 100 {
		t.Errorf("expected 100 events, got %d", result.EventsProcessed)
	}

	// Throughput should still be reasonable
	if result.EventsPerSecond < 10 {
		t.Errorf("expected at least 10 events/sec for large events, got %f", result.EventsPerSecond)
	}
}

// Test benchmark determinism
func TestBenchmarkDeterminism(t *testing.T) {
	config := benchmark.Config{
		Tier:       1,
		Events:     1000,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
	}

	result1, _ := benchmark.Run(config)
	result2, _ := benchmark.Run(config)

	if result1.EventsProcessed != result2.EventsProcessed {
		t.Errorf("non-deterministic: %d vs %d", result1.EventsProcessed, result2.EventsProcessed)
	}
}

// Test LogHub dataset import
func TestLogHubImport(t *testing.T) {
	// Create a temporary log file simulating LogHub format
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")

	f, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}

	// Write some test log lines
	g := generator.NewFirewallGenerator(generator.FirewallConfig{
		Seed:     42,
		Hostname: "test-fw",
	})

	for i := 0; i < 100; i++ {
		event, _ := g.GenerateAllow()
		fmt.Fprintf(f, "%s\n", event.Payload)
	}
	f.Close()

	// Import the file
	config := benchmark.ImportConfig{
		Path:      logFile,
		Format:    "regex",
		SourceID:  "firewall",
		Regex:     `(?P<timestamp>\S+) (?P<action>\S+) src=(?P<src_ip>[\d.]+) dst=(?P<dst_ip>[\d.]+)`,
	}

	result, err := benchmark.ImportFile(config)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if result.EventsProcessed != 100 {
		t.Errorf("expected 100 events, got %d", result.EventsProcessed)
	}
}

// Test LogHub dataset streaming import
func TestLogHubStreamingImport(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "streaming.log")

	f, _ := os.Create(logFile)
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(f, `{"timestamp":"2023-01-01T00:00:00Z","event":"test-%d"}`+"\n", i)
	}
	f.Close()

	config := benchmark.ImportConfig{
		Path:      logFile,
		Format:    "json",
		SourceID:  "test",
	}

	result, err := benchmark.ImportFile(config)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if result.EventsProcessed != 1000 {
		t.Errorf("expected 1000 events, got %d", result.EventsProcessed)
	}
}

// Test import with malformed lines
func TestImportMalformedLines(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "malformed.log")

	f, _ := os.Create(logFile)
	// Mix valid and invalid lines
	for i := 0; i < 100; i++ {
		if i%10 == 0 {
			fmt.Fprintf(f, "this is not valid json\n")
		} else {
			fmt.Fprintf(f, `{"event":"valid-%d"}`+"\n", i)
		}
	}
	f.Close()

	config := benchmark.ImportConfig{
		Path:      logFile,
		Format:    "json",
		SourceID:  "test",
	}

	result, err := benchmark.ImportFile(config)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	// Should process 90 valid lines
	if result.EventsProcessed != 90 {
		t.Errorf("expected 90 valid events, got %d", result.EventsProcessed)
	}

	// Should have 10 errors
	if result.Errors != 10 {
		t.Errorf("expected 10 errors, got %d", result.Errors)
	}
}

// Test import with file rotation
func TestImportFileRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "rotate.log")

	f, _ := os.Create(logFile)
	for i := 0; i < 100; i++ {
		fmt.Fprintf(f, `{"event":"line-%d"}`+"\n", i)
	}
	f.Close()

	config := benchmark.ImportConfig{
		Path:      logFile,
		Format:    "json",
		SourceID:  "test",
	}

	result, err := benchmark.ImportFile(config)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if result.EventsProcessed != 100 {
		t.Errorf("expected 100 events, got %d", result.EventsProcessed)
	}
}

// Test benchmark report generation
func TestBenchmarkReport(t *testing.T) {
	config := benchmark.Config{
		Tier:       1,
		Events:     1000,
		Format:     "json",
		SourceID:   "test",
		Seed:       42,
	}

	result, err := benchmark.Run(config)
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}

	report := result.Report()
	if len(report) == 0 {
		t.Error("expected non-empty report")
	}

	t.Logf("Benchmark report:\n%s", report)
}