package parquet_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/parquet"
)

func TestParquetArchiveAndRetrieve(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	events := []parquet.RawEvent{
		{
			RawEventID:  "01HXYZ",
			SourceID:    "firewall",
			ReceivedAt:  time.Now(),
			Payload:     []byte("firewall event 1"),
			PayloadHash: hashBytes([]byte("firewall event 1")),
			Sequence:    1,
		},
		{
			RawEventID:  "01HXY0",
			SourceID:    "linux",
			ReceivedAt:  time.Now(),
			Payload:     []byte("linux event 1"),
			PayloadHash: hashBytes([]byte("linux event 1")),
			Sequence:    2,
		},
	}

	for _, e := range events {
		if err := a.Archive(e); err != nil {
			t.Fatalf("archive failed: %v", err)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	for _, e := range events {
		retrieved, err := a2.Retrieve(e.RawEventID)
		if err != nil {
			t.Fatalf("retrieve failed for %s: %v", e.RawEventID, err)
		}

		if retrieved.RawEventID != e.RawEventID {
			t.Errorf("ID mismatch: got %s, want %s", retrieved.RawEventID, e.RawEventID)
		}

		if !bytes.Equal(retrieved.Payload, e.Payload) {
			t.Errorf("payload mismatch for %s", e.RawEventID)
		}

		if retrieved.PayloadHash != e.PayloadHash {
			t.Errorf("hash mismatch for %s", e.RawEventID)
		}
	}
}

func TestParquetByteForBytePreservation(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	testInputs := [][]byte{
		[]byte("Hello 世界 🌡️"),
		{0xFF, 0xFE, 0x00, 0x01, 0xC0, 0xC1},
		[]byte("before\x00after\x00\x00end"),
		[]byte(`\n\t\r\"\\`),
		[]byte("col1\tcol2\tcol3"),
		make([]byte, 10000),
	}

	for i, input := range testInputs {
		e := parquet.RawEvent{
			RawEventID:  fmt.Sprintf("evt-%03d", i),
			SourceID:    "test",
			ReceivedAt:  time.Now(),
			Payload:     input,
			PayloadHash: hashBytes(input),
			Sequence:    int64(i),
		}

		if err := a.Archive(e); err != nil {
			t.Fatalf("archive failed: %v", err)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	for i, input := range testInputs {
		id := fmt.Sprintf("evt-%03d", i)
		retrieved, err := a2.Retrieve(id)
		if err != nil {
			t.Fatalf("retrieve failed for %s: %v", id, err)
		}

		if !bytes.Equal(retrieved.Payload, input) {
			t.Errorf("byte mismatch at index %d (len %d vs %d)", i, len(retrieved.Payload), len(input))
		}
	}
}

func TestParquetPartitioning(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	sources := []string{"firewall", "linux", "web", "database"}
	for i, source := range sources {
		e := parquet.RawEvent{
			RawEventID:  fmt.Sprintf("src-%s-%d", source, i),
			SourceID:    source,
			ReceivedAt:  time.Now(),
			Payload:     []byte("event from " + source),
			PayloadHash: hashBytes([]byte("event from " + source)),
			Sequence:    int64(i),
		}

		if err := a.Archive(e); err != nil {
			t.Fatalf("archive failed: %v", err)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	for _, source := range sources {
		sourceDir := filepath.Join(dir, "source_id="+source)
		if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
			t.Errorf("partition directory not found: %s", sourceDir)
		}
	}
}

func TestParquetImmutability(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	e := parquet.RawEvent{
		RawEventID:  "test-001",
		SourceID:    "test",
		ReceivedAt:  time.Now(),
		Payload:     []byte("original payload"),
		PayloadHash: hashBytes([]byte("original payload")),
		Sequence:    1,
	}

	if err := a.Archive(e); err != nil {
		t.Fatalf("archive failed: %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	retrieved, err := a2.Retrieve("test-001")
	if err != nil {
		t.Fatalf("retrieve failed: %v", err)
	}

	if !bytes.Equal(retrieved.Payload, []byte("original payload")) {
		t.Error("payload was modified")
	}

	expectedHash := hashBytes([]byte("original payload"))
	if retrieved.PayloadHash != expectedHash {
		t.Error("hash mismatch")
	}
}

func TestParquetLargeVolume(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 500,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	for i := 0; i < 1000; i++ {
		payload := []byte(fmt.Sprintf("event payload %d", i))
		e := parquet.RawEvent{
			RawEventID:  fmt.Sprintf("evt-%04d", i),
			SourceID:    "test",
			ReceivedAt:  time.Now(),
			Payload:     payload,
			PayloadHash: hashBytes(payload),
			Sequence:    int64(i),
		}

		if err := a.Archive(e); err != nil {
			t.Fatalf("archive failed at %d: %v", i, err)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	count, err := a2.Count()
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}

	if count != 1000 {
		t.Errorf("expected 1000 events, got %d", count)
	}
}

func TestParquetEmptyArchive(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}
	defer a.Close()

	_, err = a.Retrieve("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent event")
	}

	count, err := a.Count()
	if err != nil {
		t.Fatalf("count failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 events, got %d", count)
	}
}

func TestParquetHashVerification(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	payload := []byte("test payload")
	e := parquet.RawEvent{
		RawEventID:  "hash-test",
		SourceID:    "test",
		ReceivedAt:  time.Now(),
		Payload:     payload,
		PayloadHash: hashBytes(payload),
		Sequence:    1,
	}

	if err := a.Archive(e); err != nil {
		t.Fatalf("archive failed: %v", err)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	retrieved, err := a2.Retrieve("hash-test")
	if err != nil {
		t.Fatalf("retrieve failed: %v", err)
	}

	computedHash := hashBytes(retrieved.Payload)
	if computedHash != retrieved.PayloadHash {
		t.Error("hash verification failed")
	}
}

func TestParquetQueryBySource(t *testing.T) {
	dir := t.TempDir()

	cfg := parquet.Config{
		Path:          dir,
		EventsPerFile: 1000,
	}

	a, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to create archive: %v", err)
	}

	for i := 0; i < 10; i++ {
		e := parquet.RawEvent{
			RawEventID:  fmt.Sprintf("fw-%03d", i),
			SourceID:    "firewall",
			ReceivedAt:  time.Now(),
			Payload:     []byte("firewall event"),
			PayloadHash: hashBytes([]byte("firewall event")),
			Sequence:    int64(i),
		}

		if err := a.Archive(e); err != nil {
			t.Fatalf("archive failed: %v", err)
		}
	}

	if err := a.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	a2, err := parquet.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen archive: %v", err)
	}
	defer a2.Close()

	events, err := a2.QueryBySource("firewall")
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if len(events) != 10 {
		t.Errorf("expected 10 events, got %d", len(events))
	}
}

func hashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}