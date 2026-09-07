package clickhouse_test

import (
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/clickhouse"
)

// Test ClickHouse raw event index creation
func TestClickHouseRawEventIndex(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Create tables
	if err := store.CreateTables(); err != nil {
		t.Fatalf("failed to create tables: %v", err)
	}

	// Insert a raw event
	rawEvent := clickhouse.RawEventIndex{
		RawEventID:  "01HXYZ",
		SourceID:    "firewall",
		ReceivedAt:  time.Now(),
		PayloadHash: "abc123",
		PayloadSize: 1024,
		Sequence:    1,
	}

	if err := store.InsertRawEvent(rawEvent); err != nil {
		t.Fatalf("failed to insert raw event: %v", err)
	}

	// Query back
	event, err := store.GetRawEvent("01HXYZ")
	if err != nil {
		t.Fatalf("failed to get raw event: %v", err)
	}

	if event.RawEventID != "01HXYZ" {
		t.Errorf("expected raw_event_id=01HXYZ, got %s", event.RawEventID)
	}

	if event.SourceID != "firewall" {
		t.Errorf("expected source_id=firewall, got %s", event.SourceID)
	}
}

// Test ClickHouse OCSF events table
func TestClickHouseOCSFEvents(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Insert OCSF event
	ocsfEvent := clickhouse.OCSFEvent{
		RawEventID:    "01HXYZ",
		SourceID:      "firewall",
		IngestTime:    time.Now(),
		EventTime:     time.Now(),
		OCSFCategory:  "network",
		OCSFClass:     "network_activity",
		OCSFType:      "1",
		TypeUid:       "1",
		Severity:      "low",
		ActivityID:    "allow",
		SrcEndpointIP: "10.0.0.1",
		DstEndpointIP: "8.8.8.8",
		Metadata:      "{}",
	}

	if err := store.InsertOCSFEvent(ocsfEvent); err != nil {
		t.Fatalf("failed to insert OCSF event: %v", err)
	}

	// Query back
	events, err := store.QueryOCSFEvents(clickhouse.QueryFilter{
		SourceID: "firewall",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("failed to query OCSF events: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].SrcEndpointIP != "10.0.0.1" {
		t.Errorf("expected src_ip=10.0.0.1, got %s", events[0].SrcEndpointIP)
	}
}

// Test ClickHouse processing errors table
func TestClickHouseProcessingErrors(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Insert processing error
	error := clickhouse.ProcessingError{
		RawEventID:   "01HXYZ",
		FailureType:  "parse_error",
		ParserID:     "firewall-v1",
		ParserVersion: "1.0.0",
		Error:        "invalid format",
		Timestamp:    time.Now(),
	}

	if err := store.InsertProcessingError(error); err != nil {
		t.Fatalf("failed to insert processing error: %v", err)
	}

	// Query back
	errors, err := store.QueryProcessingErrors(clickhouse.QueryFilter{
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("failed to query processing errors: %v", err)
	}

	if len(errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errors))
	}

	if errors[0].FailureType != "parse_error" {
		t.Errorf("expected failure_type=parse_error, got %s", errors[0].FailureType)
	}
}

// Test ClickHouse ingestion metrics table
func TestClickHouseIngestionMetrics(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Insert metric
	metric := clickhouse.IngestionMetric{
		Timestamp:   time.Now(),
		SourceID:    "firewall",
		MetricName:  "events_received",
		MetricValue: 100,
	}

	if err := store.InsertMetric(metric); err != nil {
		t.Fatalf("failed to insert metric: %v", err)
	}

	// Query back
	metrics, err := store.QueryMetrics(clickhouse.QueryFilter{
		SourceID: "firewall",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("failed to query metrics: %v", err)
	}

	if len(metrics) != 1 {
		t.Fatalf("expected 1 metric, got %d", len(metrics))
	}

	if metrics[0].MetricValue != 100 {
		t.Errorf("expected metric_value=100, got %d", metrics[0].MetricValue)
	}
}

// Test ClickHouse batch insert
func TestClickHouseBatchInsert(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Batch insert OCSF events
	events := []clickhouse.OCSFEvent{
		{RawEventID: "event-1", SourceID: "firewall", OCSFClass: "network_activity"},
		{RawEventID: "event-2", SourceID: "firewall", OCSFClass: "network_activity"},
		{RawEventID: "event-3", SourceID: "firewall", OCSFClass: "network_activity"},
	}

	if err := store.BatchInsertOCSFEvents(events); err != nil {
		t.Fatalf("failed to batch insert: %v", err)
	}

	// Query back
	stored, err := store.QueryOCSFEvents(clickhouse.QueryFilter{
		SourceID: "firewall",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(stored) != 3 {
		t.Errorf("expected 3 events, got %d", len(stored))
	}
}

// Test ClickHouse query with time range filter
func TestClickHouseTimeRangeQuery(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	now := time.Now()

	// Insert events at different times
	events := []clickhouse.OCSFEvent{
		{RawEventID: "old-event", SourceID: "firewall", EventTime: now.Add(-1 * time.Hour)},
		{RawEventID: "new-event", SourceID: "firewall", EventTime: now},
	}

	if err := store.BatchInsertOCSFEvents(events); err != nil {
		t.Fatalf("failed to batch insert: %v", err)
	}

	// Query with time range
	stored, err := store.QueryOCSFEvents(clickhouse.QueryFilter{
		SourceID:  "firewall",
		StartTime: now.Add(-30 * time.Minute),
		EndTime:   now.Add(30 * time.Second),
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(stored) != 1 {
		t.Errorf("expected 1 event in time range, got %d", len(stored))
	}
}

// Test ClickHouse traceability query
func TestClickHouseTraceability(t *testing.T) {
	config := clickhouse.Config{
		Addr:     "localhost:9000",
		Database: "ulpf_test",
	}

	store, err := clickhouse.New(config)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Insert raw event and OCSF event
	rawEvent := clickhouse.RawEventIndex{
		RawEventID:  "trace-001",
		SourceID:    "firewall",
		ReceivedAt:  time.Now(),
		PayloadHash: "hash123",
		PayloadSize: 512,
		Sequence:    1,
	}

	if err := store.InsertRawEvent(rawEvent); err != nil {
		t.Fatalf("failed to insert raw event: %v", err)
	}

	ocsfEvent := clickhouse.OCSFEvent{
		RawEventID:      "trace-001",
		SourceID:        "firewall",
		IngestTime:      time.Now(),
		EventTime:       time.Now(),
		OCSFClass:       "network_activity",
		SrcEndpointIP:   "10.0.0.1",
		DstEndpointIP:   "8.8.8.8",
		ParserConfigHash: "parser-hash-123",
	}

	if err := store.InsertOCSFEvent(ocsfEvent); err != nil {
		t.Fatalf("failed to insert OCSF event: %v", err)
	}

	// Traceability query: find OCSF events from a specific raw event
	events, err := store.QueryOCSFEvents(clickhouse.QueryFilter{
		RawEventID: "trace-001",
		Limit:      10,
	})
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if events[0].ParserConfigHash != "parser-hash-123" {
		t.Error("traceability: parser config hash mismatch")
	}
}