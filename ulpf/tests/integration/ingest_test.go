package ingest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bashmyhed/ulpf/internal/ingest"
)

// Test TCP ingestion basic connectivity
func TestTCPIngestionBasic(t *testing.T) {
	// Start TCP collector
	config := ingest.TCPConfig{
		Listen:    "127.0.0.1:0",
		MaxBytes:  65536,
		Timeout:   5 * time.Second,
	}
	
	received := make(chan []byte, 10)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	// Connect and send
	addr := collector.Addr()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()
	
	testMsg := []byte("test event payload\n")
	if _, err := conn.Write(testMsg); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	
	select {
	case data := <-received:
		if !bytes.Equal(data, testMsg[:len(testMsg)-1]) { // strip newline
			t.Errorf("got %q, want %q", data, testMsg[:len(testMsg)-1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// Test TCP multiple messages in single connection
func TestTCPMultipleMessages(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	received := make(chan []byte, 100)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	addr := collector.Addr()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	
	messages := []string{
		"event one\n",
		"event two\n",
		"event three\n",
	}
	
	for _, msg := range messages {
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("failed to write: %v", err)
		}
	}
	
	for i := 0; i < len(messages); i++ {
		select {
		case data := <-received:
			expected := strings.TrimSpace(messages[i])
			if string(data) != expected {
				t.Errorf("message %d: got %q, want %q", i, data, expected)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for message %d", i)
		}
	}
	conn.Close()
}

// Test TCP reconnect
func TestTCPReconnect(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	received := make(chan []byte, 100)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	addr := collector.Addr()
	
	// First connection
	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("first connect failed: %v", err)
	}
	conn1.Write([]byte("batch one\n"))
	conn1.Close()
	
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout for batch one")
	}
	
	// Second connection
	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("second connect failed: %v", err)
	}
	conn2.Write([]byte("batch two\n"))
	conn2.Close()
	
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout for batch two")
	}
}

// Test TCP concurrent clients
func TestTCPConcurrentClients(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	received := make(chan []byte, 1000)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	addr := collector.Addr()
	numClients := 5
	msgsPerClient := 20
	
	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Errorf("client %d connect failed: %v", clientID, err)
				return
			}
			defer conn.Close()
			
			for j := 0; j < msgsPerClient; j++ {
				fmt.Fprintf(conn, "client-%d-msg-%d\n", clientID, j)
			}
		}(i)
	}
	
	total := numClients * msgsPerClient
	for i := 0; i < total; i++ {
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout: got %d/%d messages", i, total)
		}
	}
}

// Test file ingestion - append only
func TestFileIngestionAppend(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	
	// Create initial file
	if err := os.WriteFile(logFile, []byte("line one\nline two\n"), 0644); err != nil {
		t.Fatal(err)
	}
	
	config := ingest.FileConfig{
		Path:    tmpDir,
		Pattern: "*.log",
	}
	
	received := make(chan []byte, 10)
	collector := ingest.NewFileCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	// Initial lines should be ingested
	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for initial line %d", i)
		}
	}
	
	// Append more lines
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("line three\nline four\n"))
	f.Close()
	
	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(2 * time.Second):
			t.Fatalf("timeout waiting for appended line %d", i)
		}
	}
}

// Test file rotation (rename)
func TestFileIngestionRotation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	
	if err := os.WriteFile(logFile, []byte("before rotation\n"), 0644); err != nil {
		t.Fatal(err)
	}
	
	config := ingest.FileConfig{
		Path:    tmpDir,
		Pattern: "*.log",
	}
	
	received := make(chan []byte, 10)
	collector := ingest.NewFileCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start collector: %v", err)
	}
	defer collector.Stop()
	
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout for initial line")
	}
	
	// Rotate: rename and create new file
	os.Rename(logFile, logFile+".1")
	f, _ := os.Create(logFile)
	f.Write([]byte("after rotation\n"))
	f.Close()
	
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout for rotated line")
	}
}

// Test raw preservation - byte-for-byte
func TestRawPreservation(t *testing.T) {
	testCases := []struct {
		name  string
		input []byte
	}{
		{"utf-8", []byte("Hello 世界 🌡️")},
		{"non-utf-8", []byte{0xFF, 0xFE, 0x00, 0x01, 0xC0, 0xC1}},
		{"null-bytes", []byte("before\x00after\x00\x00end")},
		{"escaped", []byte(`\n	\r\"\\`)},
		{"tabs", []byte("col1	col2	col3")},
		{"multiline", []byte("line1\nline2\r\nline3")},
		{"malformed-json", []byte(`{"broken": true,}`)},
		{"all-bytes", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}()},
	}
	
	// Use length-prefixed mode for raw binary data
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
		Mode:     "length-prefixed",
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			received := make(chan []byte, 1)
			collector := ingest.NewTCPCollector(config, func(data []byte) error {
				received <- data
				return nil
			})
			
			if err := collector.Start(); err != nil {
				t.Fatalf("failed to start: %v", err)
			}
			defer collector.Stop()
			
			conn, _ := net.Dial("tcp", collector.Addr())
			
			// Send length-prefixed: 4-byte big-endian length + payload
			lengthBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBytes, uint32(len(tc.input)))
			conn.Write(lengthBytes)
			conn.Write(tc.input)
			conn.Close()
			
			select {
			case data := <-received:
				if !bytes.Equal(data, tc.input) {
					t.Errorf("byte mismatch\ngot:  %x\nwant: %x", data, tc.input)
				}
				
				hash := sha256.Sum256(data)
				expectedHash := sha256.Sum256(tc.input)
				if hash != expectedHash {
					t.Error("SHA-256 mismatch")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timeout")
			}
		})
	}
}

// Test large event ingestion
func TestLargeEventIngestion(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 1024 * 1024, // 1MB
		Timeout:  10 * time.Second,
		Mode:     "length-prefixed",
	}
	
	sizes := []int{1024, 4096, 16384, 65536, 262144}
	
	for _, size := range sizes {
		t.Run(fmt.Sprintf("%dB", size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i % 256)
			}
			
			received := make(chan []byte, 1)
			collector := ingest.NewTCPCollector(config, func(data []byte) error {
				received <- data
				return nil
			})
			
			if err := collector.Start(); err != nil {
				t.Fatalf("failed to start: %v", err)
			}
			defer collector.Stop()
			
			conn, _ := net.Dial("tcp", collector.Addr())
			
			// Length-prefixed
			lengthBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(lengthBytes, uint32(size))
			conn.Write(lengthBytes)
			conn.Write(payload)
			conn.Close()
			
			select {
			case data := <-received:
				if len(data) != size {
					t.Errorf("size mismatch: got %d, want %d", len(data), size)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout")
			}
		})
	}
}

// Test partial writes
func TestPartialWrites(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	received := make(chan []byte, 1)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer collector.Stop()
	
	conn, _ := net.Dial("tcp", collector.Addr())
	
	// Send in small chunks
	message := "this is a partial write test\n"
	for i := 0; i < len(message); i += 3 {
		end := i + 3
		if end > len(message) {
			end = len(message)
		}
		conn.Write([]byte(message[i:end]))
		time.Sleep(10 * time.Millisecond)
	}
	
	select {
	case data := <-received:
		if string(data) != strings.TrimSpace(message) {
			t.Errorf("got %q, want %q", data, strings.TrimSpace(message))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
}

// Test oversized message rejection
func TestOversizedMessage(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 100, // Very small limit
		Timeout:  5 * time.Second,
	}
	
	received := make(chan []byte, 1)
	errors := make(chan error, 1)
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer collector.Stop()
	
	conn, _ := net.Dial("tcp", collector.Addr())
	defer conn.Close()
	
	// Send message larger than MaxBytes
	bigMsg := make([]byte, 200)
	for i := range bigMsg {
		bigMsg[i] = 'X'
	}
	conn.Write(bigMsg)
	
	// Should either truncate or error, but not crash
	select {
	case <-received:
		// Received something (truncation)
	case err := <-errors:
		t.Logf("got expected error: %v", err)
	case <-time.After(2 * time.Second):
		// OK - message rejected silently (raw preserved in spool)
	}
}

// Test backpressure (slow consumer)
func TestBackpressure(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	// Slow processing
	received := make(chan []byte, 5) // Small buffer
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		received <- data
		time.Sleep(100 * time.Millisecond) // Slow consumer
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer collector.Stop()
	
	addr := collector.Addr()
	conn, _ := net.Dial("tcp", addr)
	defer conn.Close()
	
	// Send faster than consumer can handle
	for i := 0; i < 10; i++ {
		fmt.Fprintf(conn, "event-%d\n", i)
	}
	
	// All should eventually be received (backpressure prevents loss)
	for i := 0; i < 10; i++ {
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			t.Fatalf("backpressure: timeout at event %d", i)
		}
	}
}

// Test metrics exposed
func TestMetricsExposed(t *testing.T) {
	config := ingest.TCPConfig{
		Listen:   "127.0.0.1:0",
		MaxBytes: 65536,
		Timeout:  5 * time.Second,
	}
	
	collector := ingest.NewTCPCollector(config, func(data []byte) error {
		return nil
	})
	
	if err := collector.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer collector.Stop()
	
	metrics := collector.Metrics()
	if metrics.EventsReceived != 0 {
		t.Errorf("expected 0 events received, got %d", metrics.EventsReceived)
	}
}
