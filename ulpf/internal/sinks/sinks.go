package sinks

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/bashmyhed/ulpf/internal/ocsf"
)

// Sink is the interface for output sinks
type Sink interface {
	Write(event *ocsf.Event) error
	Close() error
}

// JSONLSink writes events as JSON Lines
type JSONLSink struct {
	writer io.Writer
}

// NewJSONLSink creates a new JSONL sink
func NewJSONLSink(writer io.Writer) Sink {
	return &JSONLSink{writer: writer}
}

// Write writes an event as JSON
func (s *JSONLSink) Write(event *ocsf.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	_, err = s.writer.Write(data)
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	_, err = s.writer.Write([]byte("\n"))
	return err
}

// Close is a no-op for JSONL sink
func (s *JSONLSink) Close() error {
	return nil
}

// SyslogSink writes events in syslog format
type SyslogSink struct {
	writer       io.Writer
	schemaVersion string
}

// NewSyslogSink creates a new syslog sink
func NewSyslogSink(writer io.Writer, schemaVersion string) Sink {
	return &SyslogSink{writer: writer, schemaVersion: schemaVersion}
}

// Write writes an event as syslog
func (s *SyslogSink) Write(event *ocsf.Event) error {
	// Build syslog message
	priority := calculatePriority(event.Severity)
	timestamp := event.Time.Format("2006-01-02T15:04:05.000Z")
	
	// Build JSON payload
	payload, _ := json.Marshal(event)
	
	// RFC 5424 format
	msg := fmt.Sprintf("<%d>1 %s %s ulpf - - - %s\n",
		priority, timestamp, "ulpf", string(payload))

	_, err := s.writer.Write([]byte(msg))
	return err
}

// Close is a no-op for syslog sink
func (s *SyslogSink) Close() error {
	return nil
}

// HTTPSink writes events as HTTP JSON
type HTTPSink struct {
	writer io.Writer
	url    string
}

// NewHTTPSink creates a new HTTP sink
func NewHTTPSink(writer io.Writer, url string) Sink {
	return &HTTPSink{writer: writer, url: url}
}

// Write writes an event as JSON
func (s *HTTPSink) Write(event *ocsf.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	_, err = s.writer.Write(data)
	return err
}

// Close is a no-op for HTTP sink
func (s *HTTPSink) Close() error {
	return nil
}

// ParquetSink writes events in parquet format
type ParquetSink struct {
	writer io.Writer
}

// NewParquetSink creates a new parquet sink
func NewParquetSink(writer io.Writer) Sink {
	return &ParquetSink{writer: writer}
}

// Write writes an event (placeholder)
func (s *ParquetSink) Write(event *ocsf.Event) error {
	// Placeholder - would use parquet-go library
	return nil
}

// Close is a no-op for parquet sink
func (s *ParquetSink) Close() error {
	return nil
}

// ClickHouseSink writes events for ClickHouse
type ClickHouseSink struct {
	writer io.Writer
}

// NewClickHouseSink creates a new ClickHouse sink
func NewClickHouseSink(writer io.Writer) Sink {
	return &ClickHouseSink{writer: writer}
}

// Write writes an event as JSON
func (s *ClickHouseSink) Write(event *ocsf.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	_, err = s.writer.Write(data)
	return err
}

// Close is a no-op for ClickHouse sink
func (s *ClickHouseSink) Close() error {
	return nil
}

// calculatePriority calculates syslog priority from severity
func calculatePriority(severity string) int {
	switch severity {
	case "low", "info":
		return 14 // local0.info
	case "medium", "warning":
		return 12 // local0.warning
	case "high", "error":
		return 11 // local0.error
	case "critical", "alert":
		return 9 // local0.alert
	default:
		return 14
	}
}

// MultiSink writes to multiple sinks
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink creates a multi-sink
func NewMultiSink(sinks ...Sink) Sink {
	return &MultiSink{sinks: sinks}
}

// Write writes to all sinks
func (s *MultiSink) Write(event *ocsf.Event) error {
	for _, sink := range s.sinks {
		if err := sink.Write(event); err != nil {
			return err
		}
	}
	return nil
}

// Close closes all sinks
func (s *MultiSink) Close() error {
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			return err
		}
	}
	return nil
}