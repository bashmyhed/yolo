package parquet

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config configures the raw archive
type Config struct {
	Path          string
	EventsPerFile int
}

// RawEvent represents a raw event in the archive
type RawEvent struct {
	RawEventID  string    `json:"raw_event_id"`
	SourceID    string    `json:"source_id"`
	ReceivedAt  time.Time `json:"received_at"`
	Payload     []byte    `json:"payload"`
	PayloadHash string    `json:"payload_hash"`
	Sequence    int64     `json:"sequence"`
}

// Archive is an immutable raw event archive
type Archive struct {
	config       Config
	mu           sync.Mutex
	count        int64
	fileCounter  int
	pendingEvents []RawEvent
	index        map[string]string // event_id -> file path
}

// New creates a new archive
func New(cfg Config) (*Archive, error) {
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create archive dir: %w", err)
	}

	if cfg.EventsPerFile == 0 {
		cfg.EventsPerFile = 1000
	}

	a := &Archive{
		config: cfg,
		index:  make(map[string]string),
	}

	a.loadIndex()

	return a, nil
}

// Close flushes any pending events and closes the archive
func (a *Archive) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pendingEvents) > 0 {
		return a.flushUnlocked()
	}
	return nil
}

// Flush writes pending events to file
func (a *Archive) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.flushUnlocked()
}

// Archive writes a raw event to the archive
func (a *Archive) Archive(event RawEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.pendingEvents = append(a.pendingEvents, event)
	a.count++

	if len(a.pendingEvents) >= a.config.EventsPerFile {
		return a.flushUnlocked()
	}

	return nil
}

// flushUnlocked writes pending events to file (must hold lock)
func (a *Archive) flushUnlocked() error {
	if len(a.pendingEvents) == 0 {
		return nil
	}

	// Group events by source
	eventsBySource := make(map[string][]RawEvent)
	for _, e := range a.pendingEvents {
		eventsBySource[e.SourceID] = append(eventsBySource[e.SourceID], e)
	}

	for sourceID, events := range eventsBySource {
		if err := a.writeEvents(sourceID, events); err != nil {
			return err
		}
	}

	a.pendingEvents = nil
	return nil
}

func (a *Archive) writeEvents(sourceID string, events []RawEvent) error {
	partitionDir := filepath.Join(a.config.Path, "source_id="+sourceID)
	if err := os.MkdirAll(partitionDir, 0755); err != nil {
		return fmt.Errorf("failed to create partition dir: %w", err)
	}

	a.fileCounter++
	filename := fmt.Sprintf("part-%06d.jsonl", a.fileCounter)
	path := filepath.Join(partitionDir, filename)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	buf := bufio.NewWriter(f)
	defer buf.Flush()

	for _, event := range events {
		data, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal failed: %w", err)
		}

		// Write: [4-byte CRC32][4-byte length][data]
		crc := crc32.ChecksumIEEE(data)
		header := make([]byte, 8)
		header[0] = byte(crc >> 24)
		header[1] = byte(crc >> 16)
		header[2] = byte(crc >> 8)
		header[3] = byte(crc)
		header[4] = byte(len(data) >> 24)
		header[5] = byte(len(data) >> 16)
		header[6] = byte(len(data) >> 8)
		header[7] = byte(len(data))

		if _, err := buf.Write(header); err != nil {
			return err
		}
		if _, err := buf.Write(data); err != nil {
			return err
		}

		// Track index
		a.index[event.RawEventID] = path
	}

	return nil
}

// Retrieve scans all files to find an event by ID
func (a *Archive) Retrieve(rawEventID string) (*RawEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Flush pending events first
	if len(a.pendingEvents) > 0 {
		if err := a.flushUnlocked(); err != nil {
			return nil, fmt.Errorf("flush failed: %w", err)
		}
	}

	// Check index first
	if path, ok := a.index[rawEventID]; ok {
		event, err := a.readFile(path, rawEventID)
		if err == nil {
			return event, nil
		}
	}

	// Walk all files if not in index
	var found *RawEvent
	filepath.Walk(a.config.Path, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || filepath.Ext(path) != ".jsonl" {
			return nil
		}

		event, err := a.readFile(path, rawEventID)
		if err == nil {
			found = event
			return filepath.SkipAll
		}
		return nil
	})

	if found != nil {
		return found, nil
	}
	return nil, fmt.Errorf("event not found: %s", rawEventID)
}

func (a *Archive) readFile(path string, targetID string) (*RawEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)

	for {
		// Read 8-byte header
		header := make([]byte, 8)
		if _, err := io.ReadFull(reader, header); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		// Parse length
		length := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])

		// Read data
		data := make([]byte, length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, err
		}

		// Parse event
		var event RawEvent
		if err := json.Unmarshal(data, &event); err != nil {
			continue
		}

		if event.RawEventID == targetID {
			return &event, nil
		}
	}

	return nil, fmt.Errorf("not found")
}

// Count returns the total number of events in the archive
func (a *Archive) Count() (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.count, nil
}

// QueryBySource returns all events for a source
func (a *Archive) QueryBySource(sourceID string) ([]RawEvent, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.pendingEvents) > 0 {
		if err := a.flushUnlocked(); err != nil {
			return nil, err
		}
	}

	var results []RawEvent
	partitionDir := filepath.Join(a.config.Path, "source_id="+sourceID)

	filepath.Walk(partitionDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || filepath.Ext(path) != ".jsonl" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		reader := bufio.NewReader(f)

		for {
			header := make([]byte, 8)
			if _, err := io.ReadFull(reader, header); err != nil {
				break
			}

			length := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])

			data := make([]byte, length)
			if _, err := io.ReadFull(reader, data); err != nil {
				break
			}

			var event RawEvent
			if err := json.Unmarshal(data, &event); err != nil {
				continue
			}

			results = append(results, event)
		}

		return nil
	})

	return results, nil
}

// loadIndex loads the index from disk
func (a *Archive) loadIndex() {
	filepath.Walk(a.config.Path, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || filepath.Ext(path) != ".jsonl" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		reader := bufio.NewReader(f)

		for {
			header := make([]byte, 8)
			if _, err := io.ReadFull(reader, header); err != nil {
				break
			}

			length := int(header[4])<<24 | int(header[5])<<16 | int(header[6])<<8 | int(header[7])

			data := make([]byte, length)
			if _, err := io.ReadFull(reader, data); err != nil {
				break
			}

			var event RawEvent
			if err := json.Unmarshal(data, &event); err != nil {
				continue
			}

			a.index[event.RawEventID] = path
			a.count++
		}

		return nil
	})
}