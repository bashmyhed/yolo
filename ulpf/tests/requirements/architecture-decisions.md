# ULPF Architecture Decision Record (ADR)

**Version:** 1.0.0  
**Status:** Approved  
**Date:** 2026-09-07  
**Author:** Pranoy Paul

---

## ADR-001: Core Language Choice — Go

**Context:** The NTRO problem statement requires a scalable, production-ready framework. The implementation language must balance development speed, runtime performance, deployment simplicity, and ecosystem maturity.

**Decision:** Implement the core framework in Go.

**Rationale:**
- Single static binary deployment — critical for air-gapped environments
- Excellent concurrency primitives (goroutines, channels) for I/O-bound ingestion
- Strong standard library for networking, hashing, file I/O
- Low memory footprint relative to JVM/Node.js
- Cross-compilation support for Linux targets
- Well-proven in infrastructure tooling (Prometheus, Grafana Loki, Traefik, Cilium)

**Alternatives Considered:**
- Rust: Superior memory safety but longer development velocity; chosen for v2 if performance demands it
- Java: JVM warmup and memory overhead problematic on 16GB laptop
- Python: GIL limits true concurrency; runtime dependency management harder in air-gap

**Consequences:**
- Go's garbage collection pauses may impact tail latency at extreme throughput (mitigated by object pooling)
- Less expressive type system than Rust for enforcing invariants at compile time

---

## ADR-002: Raw Preservation Strategy — Spool-First

**Context:** Lossless preservation is the non-negotiable #1 principle. The architecture must guarantee that raw bytes survive any downstream failure.

**Decision:** Persist raw events to a durable local spool BEFORE any parsing or normalization occurs. The raw event is durably written before the system acknowledges receipt.

**Rationale:**
- Spool-first ensures downstream parser/sink failures never cause data loss
- Sequential disk writes are fast on laptop SSD
- Spool is bounded and replayable; it's a buffer not the archive
- Parquet archive is written asynchronously from the spool

**Alternatives Considered:**
- Write-through to Parquet directly: Parquet's append model is more complex; spool decouples ingestion from archive format
- In-memory buffer only: Violates durability on crash

**Consequences:**
- Doubles disk I/O (spool + archive) — acceptable trade-off for durability
- Spool requires crash-recovery logic (checksums, write-ahead markers)

---

## ADR-003: Immutable Parquet for Raw Archive

**Context:** Raw events need long-term, efficient, immutable storage. The archive must support forensic retrieval by ID.

**Decision:** Store raw events in Parquet files, partitioned by source_id/date/hour. Each Parquet file is written once and never modified.

**Rationale:**
- Parquet provides columnar compression (efficient for repetitive metadata fields)
- Page-level statistics enable predicate pushdown for reads
- Ecosystem-compatible (can be read by Spark, DuckDB, Pandas)
- Immutable files align with WORM compliance requirements
- Abstraction layer allows future S3/MinIO/Ceph targets

**Alternatives Considered:**
- SQLite: Mutable; not a true append-only archive
- Flat JSONL files: No compression; no columnar query optimization
- ClickHouse for raw: ClickHouse is the analytics store; raw archive must be independently authoritative

**Consequences:**
- Parquet libraries add dependency weight (using `parquet-go`)
- Small files problem at low ingestion rates (mitigated by buffering/flushing on timer)

---

## ADR-004: ClickHouse for Analytics Store

**Context:** Normalized OCSF events need a queryable, high-ingestion-rate analytical store. The store must handle billions of rows efficiently.

**Decision:** Use ClickHouse with MergeTree-family tables for the normalized event store.

**Rationale:**
- MergeTree produces immutable parts on insert — matches append-only philosophy
- Columnar storage enables fast analytical queries (aggregations, filtering)
- SQL interface accessible from any analytics tool
- Single-node deployment viable on 16GB laptop
- Excellent compression ratios for repetitive log data
- Supports materialized views for pre-aggregation

**Alternatives Considered:**
- PostgreSQL + TimescaleDB: Good but slower bulk inserts than ClickHouse
- Elasticsearch: Document-oriented overhead; less efficient for structured analytics
- DuckDB: Embedded (good for laptop) but lacks concurrent ingest capabilities
- Druid: Heavy operational overhead

**Consequences:**
- ClickHouse is not the authoritative raw archive (Parquet is)
- ClickHouse node adds resource usage on the laptop
- SQL schema must be carefully designed for query patterns

---

## ADR-005: OCSF Schema Pinning

**Context:** OCSF schema evolves over time. Runtime must not depend on external schema access. Normalized events must validate against a deterministic schema.

**Decision:** Pin OCSF schema to a specific released version (v1.8.0). Store it in `third_party/ocsf-schema/`. Validate at build time and runtime against pinned version only.

**Rationale:**
- Air-gapped deployment requires offline schema access
- Schema changes break backward compatibility; pinning ensures deterministic validation
- OCSF v1.8.0 is a stable release with broad class coverage
- Schema is fetched once at build time, never at runtime

**Consequences:**
- Manual process to upgrade schema version (intentional — prevents unexpected validation changes)
- New OCSF classes added in future versions require explicit upgrade
- Must maintain the pinned schema files in version control

---

## ADR-006: Configuration-Driven Parser Architecture

**Context:** New log sources must be onboardable without modifying ingestion core code. Parser logic must be data-driven.

**Decision:** Parsers are defined via YAML configuration. The parser framework loads configs at startup. Parsers use composable extraction stages (regex, JSON path, delimiter, key=value, syslog fields).

**Rationale:**
- YAML is human-readable, reviewable, and diffable
- Separation of parser logic from ingestion pipeline
- New source = new YAML file, zero code changes
- Configurations are versioned and hashable for lineage

**Alternatives Considered:**
- Go plugin packages (plugin.DynamicLoading): Powerful but complex; security risk in air-gap; OS-specific
- DSL/grok patterns: Requires custom parser implementation; steeper learning curve
- Rego/OPA: Overkill for field extraction

**Consequences:**
- YAML configurations are validated at startup; invalid configs rejected before processing
- Complex extraction logic may require custom Go plugins (supported but restricted)
- Parser YAML must be formally validated against a meta-schema

---

## ADR-007: Durable Local Spool Design

**Context:** The spool bridges ingestion and processing. It must be crash-safe and replayable. It exists to prevent data loss during downstream failures.

**Decision:** Implement a write-ahead log (WAL)-inspired spool with:
- Sequential append-only segment files
- Per-record CRC32 checksums
- Segment rotation at configurable size boundaries
- Write completion markers (fsync on segment close)
- Replay from last committed offset on restart

**Rationale:**
- Sequential writes maximize SSD throughput
- CRC32 detects corruption from interrupted writes
- Segment files enable bounded disk usage and cleanup
- Fsync ensures durability before acknowledgment

**Alternatives Considered:**
- BadgerDB/BoltDB: Embedded KV stores add complexity; our access pattern is append-then-consume, not random access
- mmap-based log: Platform-specific; Go's mmap support is limited

**Consequences:**
- Spool is not queryable; it's an ordered buffer
- Disk space must be monitored; spool is bounded but can fill
- Segment cleanup policy must be configurable

---

## ADR-008: Pipeline Architecture — Vertical Slices

**Context:** The system has many subsystems. Building all components in parallel risks integration failures and context loss.

**Decision:** Implement in vertical slices. Each slice goes through: tests → minimal implementation → tests pass → benchmark → refactor. Slices are ordered by dependency (ingestion before spool before archive before parser).

**Rationale:**
- Vertical slices produce working end-to-end increments
- Early detection of architectural mismatches
- Benchmarking at each stage catches performance regressions early

**Consequences:**
- Some parallelism is sacrificed (spool can't be fully tested until ingestion works)
- Integration testing happens continuously as slices connect

---

## ADR-009: Metrics and Observability

**Context:** Operators must be able to monitor system health, throughput, and failure rates. The system must expose internal state without external dependencies.

**Decision:** Use Prometheus-compatible metrics via the `client_golang` library. Expose via a `/metrics` HTTP endpoint. Key metrics include: events_received_total, events_durable_total, events_parsed_total, events_normalized_total, events_failed_total, events_quarantined_total, bytes_received_total, parse_latency, normalize_latency, queue_depth, spool_bytes.

**Rationale:**
- Prometheus exposition format is widely supported
- HTTP endpoint is simple and dependency-free
- Metrics cover all critical pipeline stages

**Consequences:**
- Larger binary due to Prometheus client dependency
- /metrics endpoint requires an HTTP server (additional port)

---

## ADR-010: AI Harness — Optional, Offline-First

**Context:** AI can accelerate parser configuration generation but must not be a runtime dependency. Air-gap compatibility is required.

**Decision:** AI harness is an optional tool that runs separately. It takes sample logs and produces parser.yaml + mapping.yaml. The output is validated and tested before activation. The AI provider interface supports pluggable backends (Ollama, OpenAI-compatible). The runtime framework has zero AI dependency.

**Rationale:**
- AI accelerates onboarding but correctness must be deterministic
- Separating AI from runtime ensures air-gap compatibility
- Generated configs are tested before activation (TDD for config)

**Consequences:**
- AI harness is not part of the Docker Compose runtime stack
- Generated configurations require human review before activation

---

## ADR-011: Traceability via Deterministic Hashing

**Context:** Every normalized event must be traceable to its exact raw bytes and processing lineage.

**Decision:** Each raw event gets a ULID-based raw_event_id. SHA-256 hash of payload is stored as payload_sha256. Each normalized event records: raw_event_id, parser_version, parser_config_hash, ocsf_schema_version, payload_sha256. Lineage is queryable via ClickHouse joins.

**Rationale:**
- ULIDs are sortable, unique, and time-ordered
- SHA-256 provides content integrity verification
- Storing lineage fields in ClickHouse enables SQL-based traceability queries

**Consequences:**
- Adds ~100 bytes overhead per normalized event for lineage fields
- Lineage must be written atomically with the normalized event

---

## ADR-012: Quarantine/Dead-Letter Path

**Context:** Malformed or unsupported events must never disappear silently. They must be recoverable and inspectable.

**Decision:** Failed events are written to a quarantine directory with: raw_event_id, failure_type, parser_id, parser_version, error message, timestamp. Quarantine entries retain a reference to the immutable raw archive. Quarantine can be reprocessed independently.

**Rationale:**
- Quarantine enables root-cause analysis and parser improvement
- Separation from normal flow prevents poisoned events from blocking the pipeline
- Reprocessing capability allows fixing parsers and re-running on quarantined data

**Consequences:**
- Quarantine grows unbounded without retention policy (configurable cleanup needed)
- Reprocessing tool must be provided

---

## ADR-013: Testing Discipline — TDD Strict

**Context:** The problem statement mandates: "Tests must be written and demonstrated before implementation of the corresponding production component."

**Decision:** For every subsystem:
1. Write test file defining expected behavior
2. Run tests (must fail — red)
3. Write minimal implementation to pass tests
4. Run tests (must pass — green)
5. Benchmark
6. Refactor

Test families T01-T25 defined in test-matrix.md. No production code ships without corresponding tests.

**Rationale:**
- Prevents "test after implementation" rationalization
- Forces clear specification before code
- Catches design flaws early

**Consequences:**
- Slower initial progress per subsystem
- Higher confidence in correctness and regression prevention

---

## ADR-014: Security Boundaries

**Context:** The system processes untrusted input. It must not execute arbitrary code, allow path traversal, or exhaust resources.

**Decision:** Hard limits enforced:
- Max configurable event size (default 64KB, configurable)
- Regex timeout (default 1s) to prevent ReDoS
- Max JSON nesting depth (default 64)
- No arbitrary code execution through config
- Plugin loading disabled by default; only enabled with explicit allowlist
- All paths sanitized; no user-controlled filesystem paths
- Bounded worker pools; bounded queue depths

**Rationale:**
- Adversarial inputs (T24) must not crash the system
- Defense in depth for a security-focused framework
- Resource exhaustion is a denial-of-service vector

**Consequences:**
- Some legitimate large events may be rejected (documented behavior)
- Regex timeout may cause false negatives on complex patterns (acceptable trade-off)

---

## ADR-015: Repository Structure

**Context:** The project needs a clear, conventional Go project layout that separates public API, internal implementation, and supporting files.

**Decision:** Follow standard Go project layout:
- `cmd/ulpf/` — CLI entrypoint
- `internal/` — Private implementation packages (ingest, spool, raw, parser, decoder, normalize, ocsf, lineage, quarantine, sinks, metrics, config)
- `pkg/plugin/` — Public plugin interface
- `configs/` — Example configurations
- `parsers/` — Parser YAML definitions
- `mappings/` — OCSF mapping YAML definitions
- `tests/` — All test suites (requirements, unit, integration, e2e, performance, failure, datasets)
- `datasets/` — Test datasets
- `docker/` — Dockerfiles
- `deploy/` — Deployment configs
- `scripts/` — Build/vendor scripts
- `third_party/` — Pinned third-party schemas (OCSF)
- `docs/` — Documentation

**Rationale:**
- Standard Go layout is familiar to contributors
- `internal/` prevents external packages from importing private APIs
- Clear separation of concerns

**Consequences:**
- Some cross-package duplication is unavoidable (e.g., shared types)
- Internal packages cannot be imported by external projects
