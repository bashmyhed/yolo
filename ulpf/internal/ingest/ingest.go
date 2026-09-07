package ingest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Metrics holds ingestion metrics
type Metrics struct {
	EventsReceived uint64
	BytesReceived  uint64
	Errors         uint64
	mu             sync.Mutex
}

// TCPConfig configures the TCP collector
type TCPConfig struct {
	Listen   string
	MaxBytes int
	Timeout  time.Duration
	Mode     string // "newline" (default) or "length-prefixed"
}

// TCPCollector collects events over TCP
type TCPCollector struct {
	config      TCPConfig
	handler     func([]byte) error
	listener    net.Listener
	mu          sync.Mutex
	metrics     Metrics
	connections []net.Conn
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

// NewTCPCollector creates a new TCP collector
func NewTCPCollector(config TCPConfig, handler func([]byte) error) *TCPCollector {
	return &TCPCollector{
		config:  config,
		handler: handler,
		stopCh:  make(chan struct{}),
	}
}

// Start begins listening for TCP connections
func (c *TCPCollector) Start() error {
	if c.config.MaxBytes == 0 {
		c.config.MaxBytes = 65536
	}
	if c.config.Timeout == 0 {
		c.config.Timeout = 30 * time.Second
	}

	listenAddr := c.config.Listen
	if listenAddr == "" {
		listenAddr = "0.0.0.0:0"
	}

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	c.listener = listener
	c.wg.Add(1)
	go c.acceptLoop()

	return nil
}

// Stop gracefully shuts down the collector
func (c *TCPCollector) Stop() {
	close(c.stopCh)
	if c.listener != nil {
		c.listener.Close()
	}
	c.mu.Lock()
	for _, conn := range c.connections {
		conn.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
}

// Addr returns the listening address
func (c *TCPCollector) Addr() string {
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return ""
}

// Metrics returns current metrics
func (c *TCPCollector) Metrics() Metrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.metrics
}

func (c *TCPCollector) acceptLoop() {
	defer c.wg.Done()

	for {
		conn, err := c.listener.Accept()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
				continue
			}
		}

		c.mu.Lock()
		c.connections = append(c.connections, conn)
		c.mu.Unlock()

		c.wg.Add(1)
		go c.handleConn(conn)
	}
}

func (c *TCPCollector) handleConn(conn net.Conn) {
	defer c.wg.Done()
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		var line []byte
		var err error

		if c.config.Mode == "length-prefixed" {
			line, err = c.readLengthPrefixed(reader)
		} else {
			line, err = c.readNewlineDelimited(reader)
		}

		if err != nil {
			return
		}

		// Skip empty
		if len(line) == 0 {
			continue
		}

		// Check size
		if len(line) > c.config.MaxBytes {
			c.mu.Lock()
			c.metrics.Errors++
			c.mu.Unlock()
			continue
		}

		hash := sha256.Sum256(line)
		_ = hex.EncodeToString(hash[:])

		if err := c.handler(line); err != nil {
			c.mu.Lock()
			c.metrics.Errors++
			c.mu.Unlock()
			continue
		}

		c.mu.Lock()
		c.metrics.EventsReceived++
		c.metrics.BytesReceived += uint64(len(line))
		c.mu.Unlock()
	}
}

func (c *TCPCollector) readNewlineDelimited(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

func (c *TCPCollector) readLengthPrefixed(reader *bufio.Reader) ([]byte, error) {
	// Read 4-byte length header
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}

	// Big-endian length
	length := binary.BigEndian.Uint32(header)
	if length > uint32(c.config.MaxBytes) {
		return nil, fmt.Errorf("message too large: %d", length)
	}

	// Read exactly `length` bytes
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// FileConfig configures the file collector
type FileConfig struct {
	Path    string
	Pattern string
}

// FileCollector collects events from files
type FileCollector struct {
	config   FileConfig
	handler  func([]byte) error
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	metrics  Metrics
	watchers map[string]*fileWatcher
}

type fileWatcher struct {
	path   string
	offset int64
	ino    uint64
}

// NewFileCollector creates a new file collector
func NewFileCollector(config FileConfig, handler func([]byte) error) *FileCollector {
	return &FileCollector{
		config:   config,
		handler:  handler,
		stopCh:   make(chan struct{}),
		watchers: make(map[string]*fileWatcher),
	}
}

// Start begins watching files
func (c *FileCollector) Start() error {
	matches, err := filepath.Glob(filepath.Join(c.config.Path, c.config.Pattern))
	if err != nil {
		return fmt.Errorf("glob failed: %w", err)
	}

	for _, path := range matches {
		w := &fileWatcher{path: path}
		c.watchers[path] = w
		c.wg.Add(1)
		go c.watchFile(w)
	}

	return nil
}

// Stop gracefully shuts down
func (c *FileCollector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
}

func (c *FileCollector) watchFile(w *fileWatcher) {
	defer c.wg.Done()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.readLines(w)
		}
	}
}

func (c *FileCollector) readLines(w *fileWatcher) {
	f, err := os.Open(w.path)
	if err != nil {
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return
	}

	currentSize := info.Size()

	// Truncation or new file
	if currentSize < w.offset {
		w.offset = 0
	}

	if currentSize == w.offset {
		return
	}

	if _, err := f.Seek(w.offset, 0); err != nil {
		return
	}

	reader := bufio.NewReader(f)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			break
		}

		line = bytes.TrimRight(line, "\r\n")

		// Handle partial line at end of file
		if len(line) > 0 && line[len(line)-1] != '\n' {
			// Check if this is the last line
			pos, _ := f.Seek(0, 1)
			if pos >= currentSize {
				// Partial line, process it
			}
		}

		if len(line) == 0 {
			continue
		}

		hash := sha256.Sum256(line)
		_ = hex.EncodeToString(hash[:])

		if err := c.handler(line); err != nil {
			c.mu.Lock()
			c.metrics.Errors++
			c.mu.Unlock()
			break
		}

		c.mu.Lock()
		c.metrics.EventsReceived++
		c.metrics.BytesReceived += uint64(len(line))
		c.mu.Unlock()

		w.offset += int64(len(line)) + 1 // +1 for newline
	}
}
