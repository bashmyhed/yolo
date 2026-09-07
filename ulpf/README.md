# ULPF - Universal Log Pre-processing Framework

**NTRO Problem Statement 26156**

A Linux-first, Go-based framework for ingesting heterogeneous logs, preserving them losslessly, normalizing to strict OCSF, and exposing them to SIEM/analytics systems.

## Quick Start

```bash
# Build
go build -o bin/ulpf ./cmd/ulpf

# Parse a JSON log file
./bin/ulpf parse --format json --input logs.jsonl --output parsed.jsonl

# Parse syslog
./bin/ulpf parse --format syslog3164 --input /var/log/auth.log --output parsed.jsonl

# Parse with custom regex
./bin/ulpf parse --format regex --regex "(?P<ip>[\d.]+) (?P<msg>.*)" --input firewall.log

# Import dataset with OCSF mapping
./bin/ulpf dataset --format json --input dataset.jsonl --output ocsf.jsonl --source firewall --class network_activity

# Start ingestion server
./bin/ulpf ingest --config configs/ulpf.yaml

# Run benchmark
./bin/ulpf bench --events 10000 --format json
```

## Supported Log Formats

### JSON (built-in)
- Application logs, CloudFlare, AWS CloudTrail, Kubernetes audit
- Nested field extraction via JSONPath: `$.user.name`

### Syslog (built-in)
- **RFC 3164** (BSD syslog): SSH, sudo, Windows events, generic
- **RFC 5424** (structured): procid, msgid, struct_data

### Key=Value (built-in)
- Firewall logs: `src=10.0.0.1 dst=8.8.8.8 action=ALLOW`

### Regex (configurable)
- Apache Combined Log, Nginx access log
- PostgreSQL, MySQL database logs
- CEF (Common Event Format), LEEF (Log Event Extended Format)
- iptables, nftables
- sudo, auditd process execution
- DHCP, DNS query logs
- Suricata/Snort IDS/IPS alerts
- OpenVPN, IPsec VPN
- fail2ban

### Delimiter (configurable)
- CSV, TSV, custom delimiters

## Architecture

```
Sources → Go Collector → Durable Spool → Parser → Normalizer → OCSF Validator
                                                                    │
                                               ┌────────────────────┴──────┐
                                               ▼                           ▼
                                          Raw Archive                ClickHouse
                                         (immutable)               (analytics)
                                               │
                                               ▼
                                          SIEM / Wazuh
```

## Output Location

- **Parsed events**: JSONL file specified by `--output` flag (one JSON object per line)
- **Raw archive**: `data/raw/` (partitioned by source_id)
- **Spool**: `data/spool/`
- **ClickHouse**: `ulpf` database

## Repository Structure

```
ulpf/
├── cmd/
│   ├── ulpf/          # CLI entrypoint
│   ├── generator/     # Synthetic log generators
│   └── testparser/    # Parser test utility
├── internal/
│   ├── ingest/        # TCP/file ingestion
│   ├── spool/         # Durable local spool
│   ├── parser/        # Parser framework
│   ├── ocsf/          # OCSF mapping/validation
│   ├── parquet/       # Raw archive
│   ├── clickhouse/    # Analytics store
│   ├── sinks/         # SIEM export adapters
│   ├── lineage/        # Traceability
│   ├── metrics/       # Prometheus metrics
│   ├── config/        # Configuration
│   ├── ai/            # AI config harness
│   └── benchmark/     # Benchmarking
├── configs/           # YAML configurations
├── datasets/          # Sample datasets
├── docker/            # Dockerfiles
└── tests/             # All test suites
```

## License

[To be determined]

## Author

Pranoy Paul — B.Tech CSE, BPPIMT Kolkata