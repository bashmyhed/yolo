package sinks_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/bashmyhed/ulpf/internal/ocsf"
	"github.com/bashmyhed/ulpf/internal/sinks"
)

// Test JSONL export sink
func TestJSONLSink(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"
	event.DstEndpoint.IP = "8.8.8.8"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Verify output
	output := buf.String()
	if len(output) == 0 {
		t.Error("expected non-empty output")
	}

	// Verify it's valid JSON
	var parsed map[string]interface{}
	line := bytes.TrimSpace(buf.Bytes())
	if err := json.Unmarshal(line, &parsed); err != nil {
		t.Errorf("invalid JSON output: %v", err)
	}
}

// Test Syslog sink
func TestSyslogSink(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewSyslogSink(&buf, "1.8.0")

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"
	event.DstEndpoint.IP = "8.8.8.8"
	event.Severity = "low"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected non-empty output")
	}

	// Should contain priority
	if !bytes.Contains([]byte(output), []byte("<")) {
		t.Error("expected syslog priority in output")
	}
}

// Test HTTP JSON sink
func TestHTTPSink(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewHTTPSink(&buf, "http://localhost:8080")

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Error("expected non-empty output")
	}
}

// Test Parquet sink
func TestParquetSink(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewParquetSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

// Test ClickHouse sink
func TestClickHouseSink(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewClickHouseSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"
	event.DstEndpoint.IP = "8.8.8.8"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

// Test sink factory
func TestSinkFactory(t *testing.T) {
	tests := []struct {
		name    string
		sink    sinks.Sink
		wantErr bool
	}{
		{"jsonl", sinks.NewJSONLSink(nil), false},
		{"syslog", sinks.NewSyslogSink(nil, "1.8.0"), false},
		{"http", sinks.NewHTTPSink(nil, "http://localhost"), false},
		{"parquet", sinks.NewParquetSink(nil), false},
		{"clickhouse", sinks.NewClickHouseSink(nil), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sink == nil {
				t.Error("expected sink to be created")
			}
		})
	}
}

// Test sink with multiple events
func TestSinkMultipleEvents(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	events := []*ocsf.Event{
		ocsf.NewEvent("network_activity", "1.8.0"),
		ocsf.NewEvent("authentication", "1.8.0"),
		ocsf.NewEvent("process_activity", "1.8.0"),
	}

	for _, event := range events {
		if err := sink.Write(event); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Verify all events written
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
}

// Test sink with empty event
func TestSinkEmptyEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Should still write valid JSON
	var parsed map[string]interface{}
	line := bytes.TrimSpace(buf.Bytes())
	if err := json.Unmarshal(line, &parsed); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}
}

// Test sink metadata preservation
func TestSinkMetadata(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"

	if err := sink.Write(event); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	// Verify metadata is preserved
	var parsed map[string]interface{}
	line := bytes.TrimSpace(buf.Bytes())
	json.Unmarshal(line, &parsed)

	if parsed["class"] != "network_activity" {
		t.Error("class not preserved")
	}
}

// Test SIEM-compatible output format
func TestSIEMOutputFormat(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"
	event.DstEndpoint.IP = "8.8.8.8"
	event.Severity = "low"

	sink.Write(event)
	sink.Close()

	// Verify the output is SIEM-consumable JSON
	var parsed map[string]interface{}
	line := bytes.TrimSpace(buf.Bytes())
	json.Unmarshal(line, &parsed)

	// Check required SIEM fields
	requiredFields := []string{"class", "time", "severity"}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required SIEM field: %s", field)
		}
	}
}

// Test Wazuh compatibility
func TestWazuhCompatibility(t *testing.T) {
	var buf bytes.Buffer
	sink := sinks.NewJSONLSink(&buf)

	event := ocsf.NewEvent("authentication", "1.8.0")
	event.User.Name = "admin"
	event.SrcEndpoint.IP = "192.168.1.100"
	event.Severity = "medium"

	sink.Write(event)
	sink.Close()

	var parsed map[string]interface{}
	line := bytes.TrimSpace(buf.Bytes())
	json.Unmarshal(line, &parsed)

	// Wazuh expects specific fields
	if parsed["class"] != "authentication" {
		t.Error("Wazuh compatibility: class field mismatch")
	}
}