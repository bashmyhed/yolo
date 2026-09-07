package lineage_test

import (
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/lineage"
	"github.com/bashmyhed/ulpf/internal/parser"
	"github.com/bashmyhed/ulpf/internal/ocsf"
)

// Test lineage record creation
func TestLineageRecordCreation(t *testing.T) {
	record := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "config-hash-123", "ocsf-1.8.0")

	if record.RawEventID != "raw-001" {
		t.Errorf("expected raw_event_id=raw-001, got %s", record.RawEventID)
	}

	if record.SourceID != "firewall" {
		t.Errorf("expected source_id=firewall, got %s", record.SourceID)
	}

	if record.ParserID != "parser-v1" {
		t.Errorf("expected parser_id=parser-v1, got %s", record.ParserID)
	}

	if record.ParserVersion != "1.0.0" {
		t.Errorf("expected parser_version=1.0.0, got %s", record.ParserVersion)
	}

	if record.ParserConfigHash != "config-hash-123" {
		t.Errorf("expected parser_config_hash=config-hash-123, got %s", record.ParserConfigHash)
	}

	if record.OCSFSchemaVersion != "ocsf-1.8.0" {
		t.Errorf("expected ocsf_schema_version=ocsf-1.8.0, got %s", record.OCSFSchemaVersion)
	}

	if record.PayloadSHA256 == "" {
		t.Error("expected payload_sha256 to be set")
	}
}

// Test lineage from parser result
func TestLineageFromParserResult(t *testing.T) {
	p := parser.New(parser.Config{
		Format: parser.FormatJSON,
	})

	input := `{"src_ip":"10.0.0.1","action":"allow"}`
	result, err := p.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	record := lineage.FromParserResult(result, "firewall", "parser-v1", "1.0.0", "config-hash", "ocsf-1.8.0")

	if record.ParserVersion != "1.0.0" {
		t.Errorf("expected parser_version=1.0.0, got %s", record.ParserVersion)
	}

	if record.ParserConfigHash != "config-hash" {
		t.Errorf("expected config_hash=config-hash, got %s", record.ParserConfigHash)
	}
}

// Test lineage from OCSF event
func TestLineageFromOCSFEvent(t *testing.T) {
	event := ocsf.NewEvent("network_activity", "1.8.0")
	event.SrcEndpoint.IP = "10.0.0.1"

	record := lineage.FromOCSFEvent(event, "raw-001", "firewall", "parser-v1", "1.0.0", "config-hash")

	if record.RawEventID != "raw-001" {
		t.Errorf("expected raw_event_id=raw-001, got %s", record.RawEventID)
	}

	if record.OCSFSchemaVersion != "1.8.0" {
		t.Errorf("expected ocsf_schema_version=1.8.0, got %s", record.OCSFSchemaVersion)
	}
}

// Test lineage chain
func TestLineageChain(t *testing.T) {
	chain := lineage.NewChain()

	// Add records
	records := []*lineage.Record{
		{
			RawEventID:        "raw-001",
			SourceID:          "firewall",
			ParserID:          "parser-v1",
			ParserVersion:     "1.0.0",
			ParserConfigHash:  "hash-1",
			OCSFSchemaVersion: "1.8.0",
			Timestamp:         time.Now(),
		},
		{
			RawEventID:        "raw-002",
			SourceID:          "linux",
			ParserID:          "parser-v2",
			ParserVersion:     "1.0.0",
			ParserConfigHash:  "hash-2",
			OCSFSchemaVersion: "1.8.0",
			Timestamp:         time.Now(),
		},
	}

	for _, r := range records {
		chain.Add(r)
	}

	// Retrieve by raw event ID
	record, err := chain.GetByRawEventID("raw-001")
	if err != nil {
		t.Fatalf("failed to get record: %v", err)
	}

	if record.SourceID != "firewall" {
		t.Errorf("expected source_id=firewall, got %s", record.SourceID)
	}

	// Retrieve by source
	fwRecords := chain.GetBySource("firewall")
	if len(fwRecords) != 1 {
		t.Errorf("expected 1 firewall record, got %d", len(fwRecords))
	}
}

// Test lineage verification
func TestLineageVerification(t *testing.T) {
	chain := lineage.NewChain()

	record := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "config-hash", "1.8.0")
	chain.Add(record)

	// Verify record exists
	if !chain.Verify("raw-001") {
		t.Error("expected record to be verified")
	}

	// Verify non-existent record
	if chain.Verify("nonexistent") {
		t.Error("expected nonexistent record to not be verified")
	}
}

// Test lineage with duplicate events
func TestLineageDuplicateHandling(t *testing.T) {
	chain := lineage.NewChain()

	// Add same raw event twice (should update)
	record1 := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "hash-1", "1.8.0")
	chain.Add(record1)

	record2 := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "hash-1", "1.8.0")
	chain.Add(record2)

	// Should have only one record
	records := chain.GetBySource("firewall")
	if len(records) != 1 {
		t.Errorf("expected 1 record (deduped), got %d", len(records))
	}
}

// Test lineage query by time range
func TestLineageTimeRangeQuery(t *testing.T) {
	chain := lineage.NewChain()

	now := time.Now()

	// Add records at different times
	records := []*lineage.Record{
		{
			RawEventID: "old-001",
			SourceID:   "firewall",
			Timestamp:  now.Add(-1 * time.Hour),
		},
		{
			RawEventID: "new-001",
			SourceID:   "firewall",
			Timestamp:  now,
		},
	}

	for _, r := range records {
		chain.Add(r)
	}

	// Query by time range
	results := chain.GetByTimeRange(now.Add(-30*time.Minute), now.Add(30*time.Second))
	if len(results) != 1 {
		t.Errorf("expected 1 record in time range, got %d", len(results))
	}
}

// Test lineage export
func TestLineageExport(t *testing.T) {
	chain := lineage.NewChain()

	record := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "hash", "1.8.0")
	chain.Add(record)

	// Export to JSON
	json, err := chain.ExportJSON()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if len(json) == 0 {
		t.Error("expected non-empty JSON export")
	}
}

// Test lineage integrity
func TestLineageIntegrity(t *testing.T) {
	record := lineage.NewRecord("raw-001", "firewall", "parser-v1", "1.0.0", "config-hash", "1.8.0")

	// Verify all required fields are set
	if record.RawEventID == "" {
		t.Error("raw_event_id should be set")
	}
	if record.SourceID == "" {
		t.Error("source_id should be set")
	}
	if record.ParserID == "" {
		t.Error("parser_id should be set")
	}
	if record.ParserVersion == "" {
		t.Error("parser_version should be set")
	}
	if record.ParserConfigHash == "" {
		t.Error("parser_config_hash should be set")
	}
	if record.OCSFSchemaVersion == "" {
		t.Error("ocsf_schema_version should be set")
	}
	if record.PayloadSHA256 == "" {
		t.Error("payload_sha256 should be set")
	}
	if record.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
}