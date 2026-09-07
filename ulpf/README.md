# ULPF — Universal Log Pre-processing Framework

**National Technical Research Organisation (NTRO) — Problem Statement 26156**

A Linux-first, Go-based framework for ingesting heterogeneous logs, preserving them losslessly, normalizing to strict OCSF, and exposing them to SIEM/analytics systems.

---

## Quick Start

```bash
# Build
make build

# Run with demo configuration
make demo

# Run tests
make test

# Run benchmarks
make benchmark

# Import LogHub datasets
make dataset-loghub
```

## Architecture

```
Sources → Go Collector → Durable Spool → Parser → Normalizer → OCSF Validator
                                                                    │
                                               ┌────────────────────┴──────┐
                                               ▼                           ▼
                                          Parquet Lake              ClickHouse
                                         (authoritative)           (analytics)
                                               │
                                               ▼
                                          SIEM / Analytics
```

## Documentation

- [Architecture](docs/architecture.md) (2-page competition deliverable)
- [Parser Development](docs/parser-development.md)
- [OCSF Mapping](docs/ocsf-mapping.md)
- [Air-Gapped Deployment](docs/air-gapped-deployment.md)
- [Performance](docs/performance.md)
- [AI Config Generator](docs/ai-config-generator.md)
- [Wazuh Integration](docs/wazuh-integration.md)

## Repository Structure

```
ulpf/
├── cmd/ulpf/          # CLI entrypoint
├── internal/          # Private implementation
├── pkg/plugin/        # Public plugin interface
├── configs/           # Example configurations
├── parsers/           # Parser YAML definitions
├── mappings/          # OCSF mapping YAML definitions
├── tests/             # All test suites
├── datasets/          # Test datasets
├── docker/            # Dockerfiles
├── deploy/            # Deployment configs
├── scripts/           # Build/vendor scripts
├── third_party/       # Pinned OCSF schema
└── docs/              # Documentation
```

## License

[To be determined]

## Author

Pranoy Paul — B.Tech CSE, BPPIMT Kolkata
