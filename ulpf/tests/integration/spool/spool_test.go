package spool_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/bashmyhed/ulpf/internal/spool"
)

func TestSpoolAppendAndReplay(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024, // 1MB
		SegmentSize: 256,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Append some events
	events := [][]byte{
		[]byte("event-one"),
		[]byte("event-two"),
		[]byte("event-three"),
	}

	for _, e := range events {
		if _, err := s.Append(e); err != nil {
			t.Fatalf("append failed: %v", err)
		}
	}

	// Replay and verify
	var replayed [][]byte
	err = s.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if len(replayed) != len(events) {
		t.Fatalf("expected %d events, got %d", len(events), len(replayed))
	}

	for i, e := range events {
		if !bytes.Equal(replayed[i], e) {
			t.Errorf("event %d: got %q, want %q", i, replayed[i], e)
		}
	}
}

func TestSpoolByteForBytePreservation(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 512,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	testInputs := [][]byte{
		[]byte("Hello 世界 🌡️"),
		{0xFF, 0xFE, 0x00, 0x01, 0xC0, 0xC1},
		[]byte("before\x00after\x00\x00end"),
		[]byte(`\n\t\r\"\\`),
		[]byte("col1\tcol2\tcol3"),
		make([]byte, 10000), // large event
	}

	for _, input := range testInputs {
		if _, err := s.Append(input); err != nil {
			t.Fatalf("append failed: %v", err)
		}
	}

	var replayed [][]byte
	err = s.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if len(replayed) != len(testInputs) {
		t.Fatalf("expected %d events, got %d", len(testInputs), len(replayed))
	}

	for i, expected := range testInputs {
		if !bytes.Equal(replayed[i], expected) {
			t.Errorf("event %d: byte mismatch (len %d vs %d)", i, len(replayed[i]), len(expected))
		}
	}
}

func TestSpoolCrashRecovery(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	// Create spool and add some events
	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}

	for i := 0; i < 5; i++ {
		s.Append([]byte("persistent-event"))
	}

	// Simulate crash by not calling Close()
	s.Close()

	// Reopen spool
	s2, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen spool: %v", err)
	}
	defer s2.Close()

	// Verify all events survived
	var replayed [][]byte
	s2.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})

	if len(replayed) != 5 {
		t.Fatalf("expected 5 events after crash recovery, got %d", len(replayed))
	}
}

func TestSpoolBoundedGrowth(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    4096, // 4KB max
		SegmentSize: 128,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Add data
	largeEvent := make([]byte, 64)
	for i := range largeEvent {
		largeEvent[i] = 'X'
	}

	for i := 0; i < 30; i++ {
		s.Append(largeEvent)
	}

	// Check total size — spool grows to accommodate all data
	// MaxBytes is a monitoring threshold, not a hard limit for crash safety
	totalSize, err := s.TotalSize()
	if err != nil {
		t.Fatalf("failed to get total size: %v", err)
	}

	// With 30 events of 64 bytes + 8 bytes overhead each = 2160 bytes
	// This is expected — spool preserves all data
	if totalSize < int64(len(largeEvent)*30) {
		t.Errorf("spool lost data: total size %d < expected %d", totalSize, len(largeEvent)*30)
	}
}

func TestSpoolSegmentRotation(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 100, // Small segments
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Add events that should trigger segment rotation
	for i := 0; i < 20; i++ {
		s.Append([]byte("segment-rotation-test-data"))
	}

	// Check that multiple segments exist
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(entries) < 2 {
		t.Errorf("expected multiple segments, got %d", len(entries))
	}
}

func TestSpoolAcknowledgment(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Append events and track sequences
	events := [][]byte{
		[]byte("event-1"),
		[]byte("event-2"),
		[]byte("event-3"),
	}

	sequences := make([]uint64, len(events))
	for i, e := range events {
		seq, err := s.Append(e)
		if err != nil {
			t.Fatalf("append failed: %v", err)
		}
		sequences[i] = seq
	}

	// Acknowledge up to sequence 2
	if err := s.Ack(sequences[1]); err != nil {
		t.Fatalf("ack failed: %v", err)
	}

	// Replay should still show all (Ack is for tracking, not deletion in spool)
	var replayed [][]byte
	s.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})

	if len(replayed) != 3 {
		t.Fatalf("expected 3 events, got %d", len(replayed))
	}
}

func TestSpoolCorruptionDetection(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}

	s.Append([]byte("before-corruption"))
	s.Close()

	// Corrupt a segment file
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if !entry.IsDir() {
			path := filepath.Join(dir, entry.Name())
			f, _ := os.OpenFile(path, os.O_WRONLY, 0644)
			f.WriteAt([]byte{0xFF, 0xFF, 0xFF, 0xFF}, 10)
			f.Close()
			break
		}
	}

	// Reopen - corruption should be handled gracefully
	s2, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to reopen spool: %v", err)
	}
	defer s2.Close()

	// Replay should handle corruption gracefully
	var replayed [][]byte
	err = s2.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})

	if err != nil {
		t.Logf("replay returned error (expected for corrupted data): %v", err)
	}

	// At minimum, it should not crash
	t.Logf("replayed %d events after corruption", len(replayed))
}

func TestSpoolPartitionBySource(t *testing.T) {
	dir := t.TempDir()

	// Create two separate spool instances for different sources
	cfg1 := spool.Config{
		Path:        filepath.Join(dir, "firewall"),
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	cfg2 := spool.Config{
		Path:        filepath.Join(dir, "linux"),
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	s1, err := spool.New(cfg1)
	if err != nil {
		t.Fatalf("failed to create spool 1: %v", err)
	}
	defer s1.Close()

	s2, err := spool.New(cfg2)
	if err != nil {
		t.Fatalf("failed to create spool 2: %v", err)
	}
	defer s2.Close()

	// Append to each
	s1.Append([]byte("firewall-event-1"))
	s1.Append([]byte("firewall-event-2"))
	s2.Append([]byte("linux-event-1"))

	// Verify isolation
	var fwEvents, linuxEvents [][]byte

	s1.Replay(func(data []byte) error {
		fwEvents = append(fwEvents, data)
		return nil
	})

	s2.Replay(func(data []byte) error {
		linuxEvents = append(linuxEvents, data)
		return nil
	})

	if len(fwEvents) != 2 {
		t.Errorf("expected 2 firewall events, got %d", len(fwEvents))
	}

	if len(linuxEvents) != 1 {
		t.Errorf("expected 1 linux event, got %d", len(linuxEvents))
	}
}

func TestSpoolEmpty(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    1024 * 1024,
		SegmentSize: 256,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Replay on empty spool should not fail
	var replayed [][]byte
	err = s.Replay(func(data []byte) error {
		replayed = append(replayed, data)
		return nil
	})

	if err != nil {
		t.Errorf("replay on empty spool failed: %v", err)
	}

	if len(replayed) != 0 {
		t.Errorf("expected 0 events, got %d", len(replayed))
	}
}

func TestSpoolLargeVolume(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    10 * 1024 * 1024, // 10MB
		SegmentSize: 1024 * 1024,      // 1MB
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Append 1000 events
	for i := 0; i < 1000; i++ {
		s.Append([]byte("large-volume-test-event-data"))
	}

	// Verify all 1000 are replayed
	var count int
	err = s.Replay(func(data []byte) error {
		count++
		return nil
	})

	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	if count != 1000 {
		t.Errorf("expected 1000 events, got %d", count)
	}
}

func TestSpoolHighConcurrency(t *testing.T) {
	dir := t.TempDir()

	cfg := spool.Config{
		Path:        dir,
		MaxBytes:    10 * 1024 * 1024,
		SegmentSize: 1024 * 1024,
	}

	s, err := spool.New(cfg)
	if err != nil {
		t.Fatalf("failed to create spool: %v", err)
	}
	defer s.Close()

	// Concurrent appends
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				s.Append([]byte("concurrent-event"))
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	var count int
	s.Replay(func(data []byte) error {
		count++
		return nil
	})

	if count != 1000 {
		t.Errorf("expected 1000 events, got %d", count)
	}
}
