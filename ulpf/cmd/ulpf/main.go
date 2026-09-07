package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bashmyhed/ulpf/internal/config"
	"github.com/bashmyhed/ulpf/internal/ingest"
	"github.com/bashmyhed/ulpf/internal/metrics"
	"github.com/bashmyhed/ulpf/internal/ocsf"
	"github.com/bashmyhed/ulpf/internal/parser"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	os.Args = os.Args[1:]

	switch command {
	case "parse":
		parseCmd()
	case "dataset":
		datasetCmd()
	case "ingest":
		ingestCmd()
	case "bench":
		benchCmd()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ULPF - Universal Log Pre-processing Framework

Usage:
  ulpf <command> [options]

Commands:
  parse      Parse a log file and output structured events
  dataset    Import a dataset file with specified format
  ingest     Start the ingestion server (TCP/file)
  bench      Run benchmarks

Examples:
  # Parse a file with JSON format
  ulpf parse --format json --input logs.jsonl --output parsed.jsonl

  # Parse with regex
  ulpf parse --format regex --regex "(?P<ip>[\d.]+) (?P<msg>.*)" --input firewall.log

  # Import dataset with OCSF mapping
  ulpf dataset --format json --input dataset.jsonl --output ocsf.jsonl --source firewall

  # Start ingestion server
  ulpf ingest --config configs/ulpf.yaml

  # Run benchmark
  ulpf bench --events 10000 --format json`)
}

func parseCmd() {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	format := fs.String("format", "json", "Parser format: json, syslog3164, syslog5424, keyvalue, regex, delimiter")
	regex := fs.String("regex", "", "Regex pattern (for regex format)")
	delimiter := fs.String("delimiter", "", "Delimiter (for delimiter format)")
	fields := fs.String("fields", "", "Comma-separated field names (for delimiter format)")
	input := fs.String("input", "", "Input file path")
	output := fs.String("output", "", "Output file path (default: stdout)")
	source := fs.String("source", "unknown", "Source ID for events")
	fs.Parse(os.Args[1:])

	if *input == "" {
		fmt.Fprintln(os.Stderr, "Error: --input is required")
		fs.Usage()
		os.Exit(1)
	}

	// Create parser config
	cfg := parser.Config{
		Format:    parser.Format(*format),
		Regex:     *regex,
		Delimiter: *delimiter,
	}

	if *fields != "" {
		cfg.Fields = strings.Split(*fields, ",")
	}

	p := parser.New(cfg)

	// Open input
	inFile, err := os.Open(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	// Open output
	var outFile *os.File
	if *output != "" {
		outFile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}

	// Parse and output
	scanner := bufio.NewScanner(inFile)
	processed := 0
	errors := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		result, err := p.Parse(line)
		if err != nil {
			errors++
			fmt.Fprintf(os.Stderr, "Parse error: %v\n", err)
			continue
		}

		// Output as JSON
		out := map[string]interface{}{
			"raw":       result.Raw,
			"fields":    result.Fields,
			"timestamp": result.Timestamp,
			"source_id": *source,
		}

		jsonBytes, _ := json.Marshal(out)
		outFile.Write(jsonBytes)
		outFile.Write([]byte("\n"))
		processed++
	}

	fmt.Fprintf(os.Stderr, "Processed %d lines, %d errors\n", processed, errors)
}

func datasetCmd() {
	fs := flag.NewFlagSet("dataset", flag.ExitOnError)
	format := fs.String("format", "json", "Parser format")
	regex := fs.String("regex", "", "Regex pattern")
	delimiter := fs.String("delimiter", "", "Delimiter")
	fields := fs.String("fields", "", "Comma-separated field names")
	input := fs.String("input", "", "Input dataset file")
	output := fs.String("output", "", "Output file path")
	source := fs.String("source", "unknown", "Source ID")
	ocsfClass := fs.String("class", "", "OCSF event class (optional)")
	fs.Parse(os.Args[1:])

	if *input == "" {
		fmt.Fprintln(os.Stderr, "Error: --input is required")
		fs.Usage()
		os.Exit(1)
	}

	// Create parser
	cfg := parser.Config{
		Format:    parser.Format(*format),
		Regex:     *regex,
		Delimiter: *delimiter,
	}
	if *fields != "" {
		cfg.Fields = strings.Split(*fields, ",")
	}
	p := parser.New(cfg)

	// Open input
	inFile, err := os.Open(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input: %v\n", err)
		os.Exit(1)
	}
	defer inFile.Close()

	// Open output
	var outFile *os.File
	if *output != "" {
		outFile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating output: %v\n", err)
			os.Exit(1)
		}
		defer outFile.Close()
	} else {
		outFile = os.Stdout
	}

	// Create OCSF mapper if class specified
	var mapper *ocsf.Mapper
	if *ocsfClass != "" {
		mapper = ocsf.NewMapper(ocsf.Config{
			SchemaVersion: "1.8.0",
			Mapping: ocsf.Mapping{
				EventClass: *ocsfClass,
			},
		})
	}

	// Process
	scanner := bufio.NewScanner(inFile)
	processed := 0
	errors := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		result, err := p.Parse(line)
		if err != nil {
			errors++
			continue
		}

		if mapper != nil {
			ocsfEvent, err := mapper.Map(result)
			if err != nil {
				errors++
				continue
			}
			jsonBytes, _ := json.Marshal(ocsfEvent)
			outFile.Write(jsonBytes)
		} else {
			out := map[string]interface{}{
				"raw":       result.Raw,
				"fields":    result.Fields,
				"timestamp": result.Timestamp,
				"source_id": *source,
			}
			jsonBytes, _ := json.Marshal(out)
			outFile.Write(jsonBytes)
		}
		outFile.Write([]byte("\n"))
		processed++
	}

	fmt.Fprintf(os.Stderr, "Processed %d lines, %d errors\n", processed, errors)
}

func ingestCmd() {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	configPath := fs.String("config", "configs/ulpf.yaml", "Config file path")
	fs.Parse(os.Args[1:])

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	metricsCollector := metrics.NewCollector()

	tcpCollector := ingest.NewTCPCollector(ingest.TCPConfig{
		Listen: cfg.Network.TCPListen,
	}, func(data []byte) error {
		metricsCollector.IncrementEventsReceived()
		metricsCollector.AddBytesReceived(int64(len(data)))
		return nil
	})

	if err := tcpCollector.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting TCP collector: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("ULPF listening on %s (TCP)\n", cfg.Network.TCPListen)

	// Wait for interrupt
	select {}
}

func benchCmd() {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	events := fs.Int("events", 10000, "Number of events")
	format := fs.String("format", "json", "Event format")
	sourceID := fs.String("source", "benchmark", "Source ID")
	fs.Parse(os.Args[1:])

	fmt.Fprintf(os.Stderr, "Benchmark: %d events, format=%s, source=%s\n", *events, *format, *sourceID)
}