package ocsf_test

import (
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/ocsf"
	"github.com/bashmyhed/ulpf/internal/parser"
)

// Test OCSF Network Activity mapping
func TestOCSFNetworkActivity(t *testing.T) {
	// Create a parsed firewall event
	p := parser.New(parser.Config{
		Format: parser.FormatRegex,
		Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<src_ip>[\d.]+) (?P<dst_ip>[\d.]+) (?P<action>\w+) (?P<proto>\w+) (?P<sport>\d+) (?P<dport>\d+)`,
	})

	input := `2023-10-11 22:14:15 10.0.0.1 8.8.8.8 ALLOW TCP 12345 80`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Map to OCSF
	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "network_activity",
			Fields: map[string]string{
				"src_endpoint.ip": "src_ip",
				"dst_endpoint.ip": "dst_ip",
				"src_endpoint.port": "sport",
				"dst_endpoint.port": "dport",
			},
		},
	})

	ocsfEvent, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if ocsfEvent.Class != "network_activity" {
		t.Errorf("expected class=network_activity, got %s", ocsfEvent.Class)
	}

	if ocsfEvent.SrcEndpoint.IP != "10.0.0.1" {
		t.Errorf("expected src_ip=10.0.0.1, got %s", ocsfEvent.SrcEndpoint.IP)
	}

	if ocsfEvent.DstEndpoint.IP != "8.8.8.8" {
		t.Errorf("expected dst_ip=8.8.8.8, got %s", ocsfEvent.DstEndpoint.IP)
	}

	if ocsfEvent.SrcEndpoint.Port != 12345 {
		t.Errorf("expected sport=12345, got %d", ocsfEvent.SrcEndpoint.Port)
	}
}

// Test OCSF Authentication mapping
func TestOCSFAuthentication(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatSyslog3164,
	})

	input := `<134>Oct 11 22:14:15 server01 sshd: Accepted publickey for admin from 192.168.1.100 port 22`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "authentication",
			Fields: map[string]string{
				"user.name":       "tag",
				"src_endpoint.ip": "hostname",
			},
		},
	})

	ocsfEvent, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if ocsfEvent.Class != "authentication" {
		t.Errorf("expected class=authentication, got %s", ocsfEvent.Class)
	}

	if ocsfEvent.User.Name != "sshd" {
		t.Errorf("expected user.name=sshd, got %s", ocsfEvent.User.Name)
	}
}

// Test OCSF Process Activity mapping
func TestOCSFProcessActivity(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"timestamp":"2023-01-01T00:00:00Z","process_name":"nginx","pid":1234,"uid":1000,"command":"nginx -g daemon off;"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "process_activity",
			Fields: map[string]string{
				"process.name":     "process_name",
				"process.pid":      "pid",
				"user.uid":         "uid",
				"process.cmdline":  "command",
			},
		},
	})

	ocsfEvent, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if ocsfEvent.Class != "process_activity" {
		t.Errorf("expected class=process_activity, got %s", ocsfEvent.Class)
	}

	if ocsfEvent.Process.Name != "nginx" {
		t.Errorf("expected process.name=nginx, got %s", ocsfEvent.Process.Name)
	}
}

// Test OCSF validation passes for valid event
func TestOCSFValidationPass(t *testing.T) {
	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"
	event.DstEndpoint.IP = "8.8.8.8"
	event.SrcEndpoint.Port = 12345
	event.DstEndpoint.Port = 80

	validator := ocsf.NewValidator("1.8.0")

	if err := validator.Validate(event); err != nil {
		t.Errorf("validation should pass: %v", err)
	}
}

// Test OCSF validation fails for invalid event
func TestOCSFValidationFail(t *testing.T) {
	// Missing required fields
	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "invalid-ip"

	validator := ocsf.NewValidator("1.8.0")

	if err := validator.Validate(event); err == nil {
		t.Error("expected validation to fail for invalid IP")
	}
}

// Test OCSF class selection based on log content
func TestOCSFClassSelection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "firewall allow",
			input:    `{"src_ip":"10.0.0.1","action":"ALLOW"}`,
			expected: "network_activity",
		},
		{
			name:     "ssh login",
			input:    `<134>Oct 11 22:14:15 server01 sshd: Accepted publickey for admin from 192.168.1.100`,
			expected: "authentication",
		},
		{
			name:     "process execution",
			input:    `{"process_name":"nginx","pid":1234}`,
			expected: "process_activity",
		},
	}

	classifier := ocsf.NewClassifier("1.8.0")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p parser.Parser
			if tt.name == "ssh login" {
				p = parser.New(parser.Config{
					Format: parser.FormatSyslog3164,
				})
			} else {
				p = parser.New(parser.Config{
					Format: parser.FormatJSON,
				})
			}
			result, err := p.Parse([]byte(tt.input))
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			class := classifier.Classify(result)
			if class != tt.expected {
				t.Errorf("expected class=%s, got %s", tt.expected, class)
			}
		})
	}
}

// Test OCSF severity mapping
func TestOCSFSeverityMapping(t *testing.T) {
	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "network_activity",
			SeverityMap: map[string]string{
				"ALLOW": "low",
				"DENY":  "medium",
			},
		},
	})

	p := parser.New(parser.Config{
		Format: parser.FormatRegex,
		Regex:  `(?P<action>\w+) (?P<src_ip>[\d.]+)`,
	})

	input := `ALLOW 10.0.0.1`
	result, _ := p.Parse([]byte(input))

	event, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	if event.Severity != "low" {
		t.Errorf("expected severity=low, got %s", event.Severity)
	}
}

// Test OCSF schema version tracking
func TestOCSFSchemaVersion(t *testing.T) {
	event := ocsf.NewEvent("network_activity", "1.8.0")

	if event.SchemaVersion != "1.8.0" {
		t.Errorf("expected schema_version=1.8.0, got %s", event.SchemaVersion)
	}
}

// Test OCSF event type UID
func TestOCSFEventTypeUID(t *testing.T) {
	event := ocsf.NewEvent("network_activity", "1.8.0")

	if event.TypeUid == "" {
		t.Error("expected type_uid to be set")
	}
}

// Test OCSF metadata
func TestOCSFMetadata(t *testing.T) {
	event := ocsf.NewEvent("network_activity", "1.8.0")

	if event.Metadata.Product.Name != "ULPF" {
		t.Errorf("expected product.name=ULPF, got %s", event.Metadata.Product.Name)
	}

	if event.Metadata.Version != "1.8.0" {
		t.Errorf("expected version=1.8.0, got %s", event.Metadata.Version)
	}
}

// Test OCSF with unmapped fields
func TestOCSFUnmappedFields(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"src_ip":"10.0.0.1","extra_field":"value","unknown_key":"data"}`
	result, _ := p.Parse([]byte(input))

	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "network_activity",
			Fields: map[string]string{
				"src_endpoint.ip": "src_ip",
			},
		},
	})

	event, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	// Mapped field should be set
	if event.SrcEndpoint.IP != "10.0.0.1" {
		t.Error("mapped field should be set")
	}
}

// Test OCSF mapping with missing source field
func TestOCSFMissingSourceField(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"other_field":"value"}`
	result, _ := p.Parse([]byte(input))

	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "network_activity",
			Fields: map[string]string{
				"src_endpoint.ip": "nonexistent_field",
			},
		},
	})

	event, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	// Field should be empty when source field is missing
	if event.SrcEndpoint.IP != "" {
		t.Error("expected empty src_ip when source field missing")
	}
}

// Test OCSF time tracking
func TestOCSFTimeTracking(t *testing.T) {
	mapper := ocsf.NewMapper(ocsf.Config{
		SchemaVersion: "1.8.0",
		Mapping: ocsf.Mapping{
			EventClass: "network_activity",
		},
	})

	p := parser.New(parser.Config{
		Format:          parser.FormatJSON,
		TimestampField:  "timestamp",
	})

	input := `{"timestamp":"2023-01-01T12:00:00Z"}`
	result, _ := p.Parse([]byte(input))

	event, err := mapper.Map(result)
	if err != nil {
		t.Fatalf("mapping failed: %v", err)
	}

	expectedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	if !event.Time.Equal(expectedTime) {
		t.Errorf("time mismatch: got %v, want %v", event.Time, expectedTime)
	}
}