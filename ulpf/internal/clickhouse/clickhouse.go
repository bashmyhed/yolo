package clickhouse

import (
	"fmt"
	"time"
)

// Config configures the ClickHouse store
type Config struct {
	Addr     string
	Database string
	Username string
	Password string
}

// RawEventIndex represents a raw event in the analytics store
type RawEventIndex struct {
	RawEventID  string
	SourceID    string
	ReceivedAt  time.Time
	PayloadHash string
	PayloadSize int64
	Sequence    int64
}

// OCSFEvent represents a normalized OCSF event in the analytics store
type OCSFEvent struct {
	RawEventID        string
	EventHash         string
	SourceID          string
	IngestTime        time.Time
	EventTime         time.Time
	OCSFCategory      string
	OCSFClass         string
	OCSFType          string
	TypeUid           string
	Severity          string
	ActivityID        string
	SrcEndpointIP     string
	SrcEndpointPort   int
	DstEndpointIP     string
	DstEndpointPort   int
	ProcessName       string
	ProcessPID        int
	UserName          string
	Metadata          string
	ParserVersion     string
	ParserConfigHash  string
	OCSFSchemaVersion string
}

// ProcessingError represents a processing error in the analytics store
type ProcessingError struct {
	RawEventID    string
	FailureType   string
	ParserID      string
	ParserVersion string
	Error         string
	Timestamp     time.Time
}

// IngestionMetric represents an ingestion metric
type IngestionMetric struct {
	Timestamp   time.Time
	SourceID    string
	MetricName  string
	MetricValue int64
}

// QueryFilter is used to filter queries
type QueryFilter struct {
	RawEventID string
	SourceID   string
	StartTime  time.Time
	EndTime    time.Time
	Limit      int
}

// Store is the ClickHouse analytics store interface
type Store interface {
	CreateTables() error
	InsertRawEvent(event RawEventIndex) error
	GetRawEvent(rawEventID string) (*RawEventIndex, error)
	InsertOCSFEvent(event OCSFEvent) error
	BatchInsertOCSFEvents(events []OCSFEvent) error
	QueryOCSFEvents(filter QueryFilter) ([]OCSFEvent, error)
	InsertProcessingError(error ProcessingError) error
	QueryProcessingErrors(filter QueryFilter) ([]ProcessingError, error)
	InsertMetric(metric IngestionMetric) error
	QueryMetrics(filter QueryFilter) ([]IngestionMetric, error)
	Close() error
}

// New creates a new ClickHouse store (in-memory for testing)
func New(config Config) (Store, error) {
	return NewInMemoryStore(), nil
}

// NewInMemoryStore creates an in-memory store for testing
func NewInMemoryStore() Store {
	return &inMemoryStore{
		rawEvents: make(map[string]RawEventIndex),
	}
}

// in-memory store for testing
type inMemoryStore struct {
	rawEvents        map[string]RawEventIndex
	ocsfEvents        []OCSFEvent
	processingErrors []ProcessingError
	metrics          []IngestionMetric
}

func (s *inMemoryStore) CreateTables() error {
	return nil
}

func (s *inMemoryStore) InsertRawEvent(event RawEventIndex) error {
	s.rawEvents[event.RawEventID] = event
	return nil
}

func (s *inMemoryStore) GetRawEvent(rawEventID string) (*RawEventIndex, error) {
	event, ok := s.rawEvents[rawEventID]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &event, nil
}

func (s *inMemoryStore) InsertOCSFEvent(event OCSFEvent) error {
	s.ocsfEvents = append(s.ocsfEvents, event)
	return nil
}

func (s *inMemoryStore) BatchInsertOCSFEvents(events []OCSFEvent) error {
	s.ocsfEvents = append(s.ocsfEvents, events...)
	return nil
}

func (s *inMemoryStore) QueryOCSFEvents(filter QueryFilter) ([]OCSFEvent, error) {
	var results []OCSFEvent
	for _, event := range s.ocsfEvents {
		if filter.RawEventID != "" && event.RawEventID != filter.RawEventID {
			continue
		}
		if filter.SourceID != "" && event.SourceID != filter.SourceID {
			continue
		}
		if !filter.StartTime.IsZero() && event.EventTime.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && event.EventTime.After(filter.EndTime) {
			continue
		}
		results = append(results, event)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results, nil
}

func (s *inMemoryStore) InsertProcessingError(error ProcessingError) error {
	s.processingErrors = append(s.processingErrors, error)
	return nil
}

func (s *inMemoryStore) QueryProcessingErrors(filter QueryFilter) ([]ProcessingError, error) {
	var results []ProcessingError
	for _, error := range s.processingErrors {
		results = append(results, error)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results, nil
}

func (s *inMemoryStore) InsertMetric(metric IngestionMetric) error {
	s.metrics = append(s.metrics, metric)
	return nil
}

func (s *inMemoryStore) QueryMetrics(filter QueryFilter) ([]IngestionMetric, error) {
	var results []IngestionMetric
	for _, metric := range s.metrics {
		if filter.SourceID != "" && metric.SourceID != filter.SourceID {
			continue
		}
		results = append(results, metric)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results, nil
}

func (s *inMemoryStore) Close() error {
	return nil
}

// Ensure inMemoryStore implements Store
var _ Store = (*inMemoryStore)(nil)