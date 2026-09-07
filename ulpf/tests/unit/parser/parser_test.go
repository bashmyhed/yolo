package parser_test

import (
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/parser"
)

// Test syslog RFC 3164 parsing
func TestSyslogRFC3164(t *testing.T) {
	input := `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`

	expected := map[string]string{
		"priority":  "34",
		"timestamp": "Oct 11 22:14:15",
		"hostname":  "mymachine",
		"tag":       "su",
		"content":   "'su root' failed for lonvick on /dev/pts/8",
	}

	p := parser.New(parser.Config{
		Format: parser.FormatSyslog3164,
	})

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test syslog RFC 5424 parsing
func TestSyslogRFC5424(t *testing.T) {
	input := `<165>1 2023-10-11T22:14:15.003Z mymachine evntslog - - - An event`

	expected := map[string]string{
		"priority":   "165",
		"version":    "1",
		"timestamp":  "2023-10-11T22:14:15.003Z",
		"hostname":   "mymachine",
		"app":        "evntslog",
		"procid":     "-",
		"msgid":      "-",
		"struct_data": "-",
		"content":    "An event",
	}

	p := parser.New(parser.Config{
		Format: parser.FormatSyslog5424,
	})

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test JSON parsing
func TestJSONParsing(t *testing.T) {
	input := `{"timestamp":"2023-01-01T00:00:00Z","src_ip":"10.0.0.1","action":"allow","port":80}`

	expected := map[string]string{
		"timestamp": "2023-01-01T00:00:00Z",
		"src_ip":    "10.0.0.1",
		"action":    "allow",
		"port":      "80",
	}

	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test key=value parsing
func TestKeyValueParsing(t *testing.T) {
	input := `src=10.0.0.1 dst=8.8.8.8 sport=12345 dport=53 proto=UDP action=ALLOW`

	expected := map[string]string{
		"src":   "10.0.0.1",
		"dst":   "8.8.8.8",
		"sport": "12345",
		"dport": "53",
		"proto": "UDP",
		"action": "ALLOW",
	}

	p := parser.New(parser.Config{
		Format: parser.FormatKeyValue,
	})

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test regex parsing
func TestRegexParsing(t *testing.T) {
	input := `2023-10-11 22:14:15 10.0.0.1 8.8.8.8 ALLOW TCP 80 443`

	config := parser.Config{
		Format: parser.FormatRegex,
		Regex:  `(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<src_ip>[\d.]+) (?P<dst_ip>[\d.]+) (?P<action>\w+) (?P<proto>\w+) (?P<sport>\d+) (?P<dport>\d+)`,
	}

	p := parser.New(config)

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expected := map[string]string{
		"timestamp": "2023-10-11 22:14:15",
		"src_ip":    "10.0.0.1",
		"dst_ip":    "8.8.8.8",
		"action":    "ALLOW",
		"proto":     "TCP",
		"sport":     "80",
		"dport":     "443",
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test Apache/Nginx combined log parsing
func TestApacheCombinedLog(t *testing.T) {
	input := `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"`

	config := parser.Config{
		Format: parser.FormatRegex,
		Regex:  `(?P<client_ip>[\d.]+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>\S+)" (?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"`,
	}

	p := parser.New(config)

	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expected := map[string]string{
		"client_ip":   "127.0.0.1",
		"timestamp":   "10/Oct/2023:13:55:36 -0700",
		"method":      "GET",
		"path":        "/",
		"proto":       "HTTP/1.1",
		"status":      "200",
		"bytes":       "2326",
		"user_agent":  "Mozilla/5.0",
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test malformed input handling
func TestMalformedInput(t *testing.T) {
	// Malformed JSON
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	_, err := p.Parse([]byte(`{broken json,}`))
	if err == nil {
		t.Error("expected error for malformed JSON")
	}

	// Malformed syslog
	p2 := parser.New(parser.Config{
		Format: parser.FormatSyslog3164,
	})

	_, err = p2.Parse([]byte(`not a syslog message`))
	if err == nil {
		t.Error("expected error for malformed syslog")
	}
}

// Test parser result structure
func TestParserResult(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"key":"value","number":"42"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if result.Raw != input {
		t.Errorf("raw mismatch: got %q, want %q", result.Raw, input)
	}

	if result.Fields["key"] != "value" {
		t.Error("field extraction failed")
	}

	if result.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

// Test parser with custom field mapping
func TestFieldMapping(t *testing.T) {
	config := parser.Config{
		Format: parser.FormatJSON,
		FieldMap: map[string]string{
			"src_ip": "source_ip",
			"dst_ip": "destination_ip",
		},
	}

	p := parser.New(config)

	input := `{"src_ip":"10.0.0.1","dst_ip":"8.8.8.8"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Mapped fields should be accessible by their mapped name
	if result.Fields["source_ip"] != "10.0.0.1" {
		t.Error("field mapping failed for source_ip")
	}

	if result.Fields["destination_ip"] != "8.8.8.8" {
		t.Error("field mapping failed for destination_ip")
	}
}

// Test parser version/hash
func TestParserVersion(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	if p.Version() == "" {
		t.Error("parser version should not be empty")
	}

	if p.ConfigHash() == "" {
		t.Error("parser config hash should not be empty")
	}
}

// Test delimiter-based parsing
func TestDelimiterParsing(t *testing.T) {
	config := parser.Config{
		Format:    parser.FormatDelimiter,
		Delimiter: ",",
		Fields:    []string{"timestamp", "src_ip", "dst_ip", "action"},
	}

	p := parser.New(config)

	input := `2023-01-01T00:00:00Z,10.0.0.1,8.8.8.8,allow`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expected := map[string]string{
		"timestamp": "2023-01-01T00:00:00Z",
		"src_ip":    "10.0.0.1",
		"dst_ip":    "8.8.8.8",
		"action":    "allow",
	}

	for key, want := range expected {
		got := result.Fields[key]
		if got != want {
			t.Errorf("field %s: got %q, want %q", key, got, want)
		}
	}
}

// Test JSON path extraction
func TestJSONPath(t *testing.T) {
	config := parser.Config{
		Format: parser.FormatJSON,
		JSONPaths: map[string]string{
			"src_ip":  "$.src_ip",
			"dst_ip":  "$.dst_ip",
			"action":  "$.action",
			"nested":  "$.metadata.user.name",
		},
	}

	p := parser.New(config)

	input := `{"src_ip":"10.0.0.1","dst_ip":"8.8.8.8","action":"allow","metadata":{"user":{"name":"admin"}}}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if result.Fields["src_ip"] != "10.0.0.1" {
		t.Error("JSON path extraction failed for src_ip")
	}

	if result.Fields["nested"] != "admin" {
		t.Error("JSON path extraction failed for nested field")
	}
}

// Test parser pipeline
func TestParserPipeline(t *testing.T) {
	// Test that multiple parsers can be chained
	p1 := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"src_ip":"10.0.0.1","action":"allow"}`
	result, err := p1.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Second parser could transform the output
	p2 := parser.New(parser.Config{
		Format: parser.FormatKeyValue,
	})

	// Convert JSON fields to key=value format
	kvInput := "src=" + result.Fields["src_ip"] + " action=" + result.Fields["action"]
	result2, err := p2.Parse([]byte(kvInput))
	if err != nil {
		t.Fatalf("second parse failed: %v", err)
	}

	if result2.Fields["src"] != "10.0.0.1" {
		t.Error("pipeline failed")
	}
}

// Test parser with empty input
func TestEmptyInput(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	_, err := p.Parse([]byte(""))
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// Test parser with binary data
func TestBinaryInput(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	binaryData := []byte{0xFF, 0xFE, 0x00, 0x01, 0xC0, 0xC1}
	_, err := p.Parse(binaryData)
	if err == nil {
		t.Error("expected error for binary input to JSON parser")
	}
}

// Test parser metadata
func TestParserMetadata(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"key":"value"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if result.ParserVersion == "" {
		t.Error("parser version should be set")
	}

	if result.ParserConfigHash == "" {
		t.Error("parser config hash should be set")
	}

	if result.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
}

// Test concurrent parsing
func TestConcurrentParsing(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			input := `{"id":"` + string(rune('0'+id)) + `"}`
			_, err := p.Parse([]byte(input))
			if err != nil {
				t.Errorf("concurrent parse failed: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test parser factory
func TestParserFactory(t *testing.T) {
	configs := []parser.Config{
		{Format: parser.FormatJSON},
		{Format: parser.FormatSyslog3164},
		{Format: parser.FormatSyslog5424},
		{Format: parser.FormatKeyValue},
		{Format: parser.FormatRegex, Regex: `(?P<test>\w+)`},
		{Format: parser.FormatDelimiter, Delimiter: ",", Fields: []string{"a", "b"}},
	}

	for _, cfg := range configs {
		p := parser.New(cfg)
		if p == nil {
			t.Errorf("failed to create parser for format %s", cfg.Format)
		}
	}
}

// Test parser error types
func TestParserErrors(t *testing.T) {
	// Invalid regex
	p := parser.New(parser.Config{
		Format: parser.FormatRegex,
		Regex:  `(?P<unclosed(`,
	})

	_, err := p.Parse([]byte("test"))
	if err == nil {
		t.Error("expected error for invalid regex")
	}

	// Missing delimiter config
	p2 := parser.New(parser.Config{
		Format: parser.FormatDelimiter,
	})

	_, err = p2.Parse([]byte("test"))
	if err == nil {
		t.Error("expected error for missing delimiter config")
	}
}

// Test parser with timestamp extraction
func TestTimestampExtraction(t *testing.T) {
	p := parser.New(parser.Config{
		Format:          parser.FormatJSON,
		TimestampField:  "timestamp",
	})

	input := `{"timestamp":"2023-01-01T12:00:00Z","event":"test"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expectedTime := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	if !result.Timestamp.Equal(expectedTime) {
		t.Errorf("timestamp mismatch: got %v, want %v", result.Timestamp, expectedTime)
	}
}

// Test parser with custom timestamp format
func TestCustomTimestampFormat(t *testing.T) {
	p := parser.New(parser.Config{
		Format:          parser.FormatJSON,
		TimestampField:  "ts",
		TimestampFormat: "2006-01-02 15:04:05",
	})

	input := `{"ts":"2023-10-11 22:14:15","event":"test"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	expectedTime := time.Date(2023, 10, 11, 22, 14, 15, 0, time.UTC)
	if !result.Timestamp.Equal(expectedTime) {
		t.Errorf("timestamp mismatch: got %v, want %v", result.Timestamp, expectedTime)
	}
}