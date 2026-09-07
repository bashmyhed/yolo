package benchmark

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config configures a benchmark run
type Config struct {
	Tier      int
	Events    int
	Format    string
	SourceID  string
	Seed      int64
	EventSize int
}

// Result holds benchmark results
type Result struct {
	EventsProcessed int
	BytesProcessed  int64
	Duration        time.Duration
	EventsPerSecond float64
	BytesPerSecond  float64
	ErrorRate       float64
	Errors          int
}

// Run executes a benchmark
func Run(config Config) (*Result, error) {
	start := time.Now()
	processed := 0
	var bytesProcessed int64
	errors := 0

	// Generate and process events
	for i := 0; i < config.Events; i++ {
		var event string
		switch config.Format {
		case "json":
			event = fmt.Sprintf(`{"timestamp":"%s","event":"test-%d","source":"%s"}`, time.Now().Format(time.RFC3339), i, config.SourceID)
		case "syslog":
			event = fmt.Sprintf("<134>1 %s %s test - - - event %d", time.Now().Format("2006-01-02T15:04:05Z07:00"), config.SourceID, i)
		case "keyvalue":
			event = fmt.Sprintf("timestamp=%s event=test-%d source=%s", time.Now().Format(time.RFC3339), i, config.SourceID)
		case "apache":
			event = fmt.Sprintf(`127.0.0.1 - - [%s] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"`, time.Now().Format("02/Jan/2006:15:04:05 -0700"))
		default:
			event = fmt.Sprintf(`{"event":"test-%d"}`, i)
		}

		bytesProcessed += int64(len(event))
		processed++
	}

	duration := time.Since(start)

	eventsPerSecond := float64(processed) / duration.Seconds()
	bytesPerSecond := float64(bytesProcessed) / duration.Seconds()

	return &Result{
		EventsProcessed: processed,
		BytesProcessed:  bytesProcessed,
		Duration:        duration,
		EventsPerSecond: eventsPerSecond,
		BytesPerSecond:  bytesPerSecond,
		ErrorRate:       float64(errors) / float64(processed),
		Errors:          errors,
	}, nil
}

// ImportConfig configures a file import
type ImportConfig struct {
	Path     string
	Format   string
	SourceID string
	Regex    string
}

// ImportFile imports events from a file
func ImportFile(config ImportConfig) (*Result, error) {
	file, err := os.Open(config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	start := time.Now()
	processed := 0
	errors := 0
	var bytesProcessed int64

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		bytesProcessed += int64(len(line))

		// Validate line based on format
		if config.Format == "json" {
			if !strings.HasPrefix(line, "{") {
				errors++
				continue
			}
		}

		processed++
	}

	duration := time.Since(start)

	return &Result{
		EventsProcessed: processed,
		BytesProcessed:  bytesProcessed,
		Duration:        duration,
		EventsPerSecond: float64(processed) / duration.Seconds(),
		BytesPerSecond:  float64(bytesProcessed) / duration.Seconds(),
		ErrorRate:       float64(errors) / float64(processed),
		Errors:          errors,
	}, nil
}

// Report generates a human-readable benchmark report
func (r *Result) Report() string {
	var sb strings.Builder
	sb.WriteString("=== Benchmark Report ===\n")
	sb.WriteString(fmt.Sprintf("Events Processed: %d\n", r.EventsProcessed))
	sb.WriteString(fmt.Sprintf("Bytes Processed: %d\n", r.BytesProcessed))
	sb.WriteString(fmt.Sprintf("Duration: %v\n", r.Duration))
	sb.WriteString(fmt.Sprintf("Events/sec: %.0f\n", r.EventsPerSecond))
	sb.WriteString(fmt.Sprintf("MB/sec: %.2f\n", r.BytesPerSecond/1024/1024))
	sb.WriteString(fmt.Sprintf("Error Rate: %.2f%%\n", r.ErrorRate*100))
	return sb.String()
}