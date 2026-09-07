package lineage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bashmyhed/ulpf/internal/ocsf"
	"github.com/bashmyhed/ulpf/internal/parser"
)

// Record represents a lineage record
type Record struct {
	RawEventID        string    `json:"raw_event_id"`
	SourceID          string    `json:"source_id"`
	ParserID          string    `json:"parser_id"`
	ParserVersion     string    `json:"parser_version"`
	ParserConfigHash  string    `json:"parser_config_hash"`
	OCSFSchemaVersion string    `json:"ocsf_schema_version"`
	PayloadSHA256     string    `json:"payload_sha256"`
	Timestamp         time.Time `json:"timestamp"`
}

// NewRecord creates a new lineage record
func NewRecord(rawEventID, sourceID, parserID, parserVersion, parserConfigHash, ocsfSchemaVersion string) *Record {
	// Compute deterministic hash from rawEventID
	hash := sha256.Sum256([]byte(rawEventID))
	return &Record{
		RawEventID:        rawEventID,
		SourceID:          sourceID,
		ParserID:          parserID,
		ParserVersion:     parserVersion,
		ParserConfigHash:  parserConfigHash,
		OCSFSchemaVersion: ocsfSchemaVersion,
		PayloadSHA256:     hex.EncodeToString(hash[:]),
		Timestamp:         time.Now().UTC(),
	}
}

// FromParserResult creates a lineage record from a parser result
func FromParserResult(result *parser.Result, sourceID, parserID, parserVersion, parserConfigHash, ocsfSchemaVersion string) *Record {
	hash := sha256.Sum256([]byte(result.Raw))
	return &Record{
		SourceID:          sourceID,
		ParserID:          parserID,
		ParserVersion:     parserVersion,
		ParserConfigHash:  parserConfigHash,
		OCSFSchemaVersion: ocsfSchemaVersion,
		PayloadSHA256:     hex.EncodeToString(hash[:]),
		Timestamp:         time.Now().UTC(),
	}
}

// FromOCSFEvent creates a lineage record from an OCSF event
func FromOCSFEvent(event *ocsf.Event, rawEventID, sourceID, parserID, parserVersion, parserConfigHash string) *Record {
	return &Record{
		RawEventID:        rawEventID,
		SourceID:          sourceID,
		ParserID:          parserID,
		ParserVersion:     parserVersion,
		ParserConfigHash:  parserConfigHash,
		OCSFSchemaVersion: event.SchemaVersion,
		Timestamp:         time.Now().UTC(),
	}
}

// Chain represents a chain of lineage records
type Chain struct {
	records map[string]*Record
}

// NewChain creates a new lineage chain
func NewChain() *Chain {
	return &Chain{
		records: make(map[string]*Record),
	}
}

// Add adds a record to the chain
func (c *Chain) Add(record *Record) {
	c.records[record.RawEventID] = record
}

// GetByRawEventID retrieves a record by raw event ID
func (c *Chain) GetByRawEventID(rawEventID string) (*Record, error) {
	record, ok := c.records[rawEventID]
	if !ok {
		return nil, fmt.Errorf("record not found: %s", rawEventID)
	}
	return record, nil
}

// GetBySource retrieves records by source ID
func (c *Chain) GetBySource(sourceID string) []*Record {
	var results []*Record
	for _, record := range c.records {
		if record.SourceID == sourceID {
			results = append(results, record)
		}
	}
	return results
}

// GetByTimeRange retrieves records within a time range
func (c *Chain) GetByTimeRange(start, end time.Time) []*Record {
	var results []*Record
	for _, record := range c.records {
		if record.Timestamp.After(start) && record.Timestamp.Before(end) {
			results = append(results, record)
		}
	}
	return results
}

// Verify checks if a record exists for the given raw event ID
func (c *Chain) Verify(rawEventID string) bool {
	_, ok := c.records[rawEventID]
	return ok
}

// ExportJSON exports all records as JSON
func (c *Chain) ExportJSON() ([]byte, error) {
	records := make([]*Record, 0, len(c.records))
	for _, record := range c.records {
		records = append(records, record)
	}
	return json.Marshal(records)
}