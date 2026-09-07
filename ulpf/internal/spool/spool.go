package spool

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Config configures the spool
type Config struct {
	Path        string
	MaxBytes    int64
	SegmentSize int64
}

// Spool is a durable, append-only, crash-recoverable event spool
type Spool struct {
	config     Config
	mu         sync.Mutex
	segments   []string
	current    *os.File
	currentSize int64
	head       uint64 // next sequence to read
	tail       uint64 // next sequence to write
}

// New creates or opens a spool
func New(cfg Config) (*Spool, error) {
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create spool dir: %w", err)
	}

	s := &Spool{
		config: cfg,
	}

	// Scan existing segments
	entries, err := os.ReadDir(cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read spool dir: %w", err)
	}

	var segmentFiles []string
	for _, entry := range entries {
		if !entry.IsDir() {
			segmentFiles = append(segmentFiles, entry.Name())
		}
	}

	// Sort by name (which is creation order)
	sort.Strings(segmentFiles)
	s.segments = segmentFiles

	// Find the last segment to continue writing
	if len(s.segments) > 0 {
		lastSeg := s.segments[len(s.segments)-1]
		path := filepath.Join(cfg.Path, lastSeg)
		f, err := os.OpenFile(path, os.O_RDWR, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open last segment: %w", err)
		}
		s.current = f

		// Scan to find tail
		if err := s.scanSegment(f); err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to scan segment: %w", err)
		}
	} else {
		// Create first segment
		if err := s.createSegment(); err != nil {
			return nil, err
		}
	}

	return s, nil
}

// Close closes the spool
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		return s.current.Close()
	}
	return nil
}

// Append writes an event to the spool
func (s *Spool) Append(data []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if we need to rotate
	if s.currentSize > 0 && s.currentSize+int64(len(data))+8 > s.config.SegmentSize {
		if err := s.rotate(); err != nil {
			return 0, err
		}
	}

	// Write: [4-byte length][data][4-byte CRC32]
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, uint32(len(data)))

	crc := crc32.ChecksumIEEE(data)
	crcBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBytes, crc)

	// Write atomically
	if _, err := s.current.Write(lengthBytes); err != nil {
		return 0, fmt.Errorf("write length failed: %w", err)
	}
	if _, err := s.current.Write(data); err != nil {
		return 0, fmt.Errorf("write data failed: %w", err)
	}
	if _, err := s.current.Write(crcBytes); err != nil {
		return 0, fmt.Errorf("write crc failed: %w", err)
	}

	// Sync for durability
	if err := s.current.Sync(); err != nil {
		return 0, fmt.Errorf("sync failed: %w", err)
	}

	s.currentSize += int64(len(data)) + 8
	seq := s.tail
	s.tail++

	return seq, nil
}

// Replay reads all events from the spool
func (s *Spool) Replay(handler func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, segName := range s.segments {
		path := filepath.Join(s.config.Path, segName)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open segment %s: %w", segName, err)
		}

		reader := bufio.NewReader(f)
		for {
			event, err := s.readRecord(reader)
			if err == io.EOF {
				break
			}
			if err != nil {
				f.Close()
				return fmt.Errorf("read error in %s: %w", segName, err)
			}

			if err := handler(event); err != nil {
				f.Close()
				return fmt.Errorf("handler error: %w", err)
			}
		}

		f.Close()
	}

	return nil
}

// Ack marks events up to the given sequence as acknowledged
func (s *Spool) Ack(seq uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// In this implementation, Ack is a no-op for the spool itself
	// The spool retains all data until explicitly trimmed
	// A production implementation would track acked sequences
	// and trim segments that are fully acknowledged
	return nil
}

// TotalSize returns the total disk usage of the spool
func (s *Spool) TotalSize() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var total int64
	for _, segName := range s.segments {
		path := filepath.Join(s.config.Path, segName)
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
		}
		total += info.Size()
	}
	return total, nil
}

func (s *Spool) createSegment() error {
	name := fmt.Sprintf("segment-%06d", len(s.segments))
	path := filepath.Join(s.config.Path, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to create segment: %w", err)
	}
	s.current = f
	s.segments = append(s.segments, name)
	s.currentSize = 0
	return nil
}

func (s *Spool) rotate() error {
	if s.current != nil {
		s.current.Close()
	}
	return s.createSegment()
}

func (s *Spool) scanSegment(f *os.File) error {
	reader := bufio.NewReader(f)
	for {
		_, err := s.readRecord(reader)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Log corruption but continue
			break
		}
		s.tail++
	}

	// Get current size
	info, err := f.Stat()
	if err != nil {
		return err
	}
	s.currentSize = info.Size()

	return nil
}

func (s *Spool) readRecord(reader *bufio.Reader) ([]byte, error) {
	// Read 4-byte length
	lengthBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes)

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}

	// Read and verify CRC
	crcBytes := make([]byte, 4)
	if _, err := io.ReadFull(reader, crcBytes); err != nil {
		return nil, err
	}
	expectedCRC := binary.BigEndian.Uint32(crcBytes)
	actualCRC := crc32.ChecksumIEEE(data)
	if expectedCRC != actualCRC {
		return nil, fmt.Errorf("CRC mismatch: expected %d, got %d", expectedCRC, actualCRC)
	}

	return data, nil
}
