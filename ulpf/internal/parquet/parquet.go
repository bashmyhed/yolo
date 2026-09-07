package parquet

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/parquet-go/parquet-go"
)

// Config configures the Parquet archive
type Config struct {
	Path          string
	EventsPerFile int
}

// RawEvent represents a raw event in the archive
type RawEvent struct {
	RawEventID  string    `parquet:"raw_event_id"`
	SourceID    string    `parquet:"source_id"`
	ReceivedAt  time.Time `parquet:"received_at"`
	Payload     []byte    `parquet:"payload"`
	PayloadHash string    `parquet:"payload_hash"`
	Sequence    int64     `parquet:"sequence"`
}

// Archive is a Parquet-backed immutable raw event archive
type Archive struct {
	config       Config
	mu           sync.Mutex
	count        int64
	fileCounter  int
	sourceCounters map[string]int // sourceID -> events written to current file

	// Writers per source (each source gets its own parquet file)
	writers     map[string]*parquet.GenericWriter[RawEvent]
	writerFiles map[string]*os.File
	writerPaths map[string]string
}

// New creates a new Parquet archive
func New(cfg Config) (*Archive, error) {
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archive dir: %w", err)
	}

	if cfg.EventsPerFile == 0 {
		cfg.EventsPerFile = 100
	}

	a := &Archive{
		config:         cfg,
		writers:        make(map[string]*parquet.GenericWriter[RawEvent]),
		writerFiles:    make(map[string]*os.File),
		writerPaths:    make(map[string]string),
		sourceCounters: make(map[string]int),
	}

	return a, nil
}

// Close closes the archive
func (a *Archive) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, w := range a.writers {
		w.Close()
	}
	for _, f := range a.writerFiles {
		f.Close()
	}
	a.writers = make(map[string]*parquet.GenericWriter[RawEvent])
	a.writerFiles = make(map[string]*os.File)
	return nil
}

// Flush is a no-op for compatibility
func (a *Archive) Flush() error {
	return nil
}

// Archive writes a raw event to the archive
func (a *Archive) Archive(event RawEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Get or create writer for this source
	writer, exists := a.writers[event.SourceID]
	if !exists || a.sourceCounters[event.SourceID] >= a.config.EventsPerFile {
		// Close existing writer for this source
		if writer != nil {
			writer.Close()
		}
		if f, ok := a.writerFiles[event.SourceID]; ok {
			f.Close()
		}

		// Create new writer for this source
		partitionDir := filepath.Join(a.config.Path, "source_id="+event.SourceID)
		if err := os.MkdirAll(partitionDir, 0755); err != nil {
			return fmt.Errorf("failed to create partition dir: %w", err)
		}

		a.fileCounter++
		filename := fmt.Sprintf("part-%06d-%d.parquet", a.fileCounter, time.Now().UnixNano())
		path := filepath.Join(partitionDir, filename)

		f, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		a.writerFiles[event.SourceID] = f
		a.writers[event.SourceID] = parquet.NewGenericWriter[RawEvent](f)
		a.writerPaths[event.SourceID] = path
		a.sourceCounters[event.SourceID] = 0
		writer = a.writers[event.SourceID]
	}

	// Write the event
	if _, err := writer.Write([]RawEvent{event}); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}

	a.count++
	a.sourceCounters[event.SourceID]++
	return nil
}

// Retrieve scans all parquet files to find an event by ID
func (a *Archive) Retrieve(rawEventID string) (*RawEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Close all writers to flush footers
	for sourceID, w := range a.writers {
		w.Close()
		if f, ok := a.writerFiles[sourceID]; ok {
			f.Close()
		}
		delete(a.writers, sourceID)
		delete(a.writerFiles, sourceID)
	}

	// Walk all parquet files in the archive directory
	var found *RawEvent
	filepath.Walk(a.config.Path, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".parquet" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		reader := parquet.NewGenericReader[RawEvent](f)
		buf := make([]RawEvent, 1)
		for {
			n, err := reader.Read(buf)
			if n == 0 || err != nil {
				break
			}
			if buf[0].RawEventID == rawEventID {
				event := buf[0]
				found = &event
				return filepath.SkipAll
			}
		}
		return nil
	})

	if found != nil {
		return found, nil
	}
	return nil, fmt.Errorf("event not found: %s", rawEventID)
}

// Count returns the total number of events in the archive
func (a *Archive) Count() (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.count, nil
}