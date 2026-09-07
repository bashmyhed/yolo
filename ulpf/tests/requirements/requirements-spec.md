# ULPF Requirements Specification

**Version:** 1.0.0  
**Date:** 2026-09-07  
**Author:** Pranoy Paul

---

## 1. Functional Requirements

### FR-001: Event Ingestion — Local Sources
- **ID:** FR-001
- **Priority:** MUST
- **Description:** The system SHALL accept events from local files, journald, stdin, Unix domain sockets, and TCP sockets.
- **Acceptance:** Configured source definitions in YAML; each event received generates a durable raw record.
- **Tests:** T02, T05, T06

### FR-002: Event Ingestion — Network Sources
- **ID:** FR-002
- **Priority:** MUST
- **Description:** The SHALL accept events over TCP syslog, UDP syslog, HTTP JSON, and HTTP plain text.
- **Acceptance:** Network listeners configurable; TCP is reliable; UDP is best-effort with documented limitations.
- **Tests:** T02

### FR-003: Event Ingestion — Remote Pull Adapters
- **ID:** FR-003
- **Priority:** SHOULD
- **Description:** The system SHALL support a pluggable adapter interface for pull-based sources.
- **Acceptance:** Mock adapters demonstrate the interface; vendor adapters can be added without core changes.
- **Tests:** (Integration with mock adapters)

### FR-004: Lossless Raw Preservation
- **ID:** FR-004
- **Priority:** MUST (non-negotiable #1)
- **Description:** Every received event MUST have its raw bytes preserved byte-for-byte before any processing is considered durable.
- **Acceptance:** SHA-256 of persisted raw matches SHA-256 of received bytes. No truncation, encoding change, or silent modification.
- **Tests:** T01, T17, T23

### FR-005: Raw Event Metadata
- **ID:** FR-005
- **Priority:** MUST
- **Description:** Every raw event SHALL include: raw_event_id, source_id, received_at, source_type, transport, sequence, payload_sha256, payload_size, payload_encoding.
- **Acceptance:** All fields populated for every raw event regardless of parse success.
- **Tests:** T01, T14, T17

### FR-006: Durable Local Spool
- **ID:** FR-006
- **Priority:** MUST
- **Description:** The system SHALL implement a disk-backed spool that is crash-recoverable, bounded, replayable, checksummed, and partitionable.
- **Acceptance:** Crash during write is detectable; replay recovers all completed writes; bounded disk usage.
- **Tests:** T19, T20, T21

### FR-007: Immutable Parquet Raw Archive
- **ID:** FR-007
- **Priority:** MUST
- **Description:** Raw events SHALL be archived to Parquet files in an immutable, partitioned layout. Files are written once and never modified.
- **Acceptance:** Parquet files are readable; schema includes all raw metadata + payload bytes; partitioning by source/date/hour.
- **Tests:** T01 (full byte-for-byte verification from archive)

### FR-008: OCSF Normalization
- **ID:** FR-008
- **Priority:** MUST
- **Description:** Parsed events SHALL be normalized to strict pinned OCSF schema (v1.8.0). Every normalized event MUST validate.
- **Acceptance:** Schema validation passes for all mapped events; unmappable fields preserved in raw; no fabricated fields.
- **Tests:** T18

### FR-009: OCSF Class Coverage (Initial)
- **ID:** FR-009
- **Priority:** MUST
- **Description:** Initial implementation SHALL support: Network Activity, Authentication, Process Activity, Application Activity, DNS Activity, HTTP Activity.
- **Acceptance:** Sample events for each class validate against schema.
- **Tests:** T07, T08, T09

### FR-010: Parser Framework — Configuration-Driven
- **ID:** FR-010
- **Priority:** MUST
- **Description:** Parsers SHALL be definable via YAML configuration without modifying ingestion code. Support regex, delimiter, JSON path, key=value, syslog fields.
- **Acceptance:** Adding a new parser = adding new YAML files; no Go code changes.
- **Tests:** T13

### FR-011: OCSF Mapping — Configuration-Driven
- **ID:** FR-011
- **Priority:** MUST
- **Description:** Field mappings from parsed events to OCSF SHALL be configurable in YAML and validated against pinned schema at startup.
- **Acceptance:** Invalid mappings rejected at startup; valid mappings produce correct OCSF.
- **Tests:** T13, T18, T25

### FR-012: Unknown/Partial Events
- **ID:** FR-012
- **Priority:** MUST
- **Description:** Events that cannot be fully mapped SHALL still produce raw archive + partial OCSF where justified, OR go to quarantine. No fabrication of fields.
- **Acceptance:** No invented IPs, usernames, severities, or classes. Quarantine entries for unmappable events.
- **Tests:** T17

### FR-013: Traceability
- **ID:** FR-013
- **Priority:** MUST
- **Description:** Every normalized event SHALL include lineage: raw_event_id, parser_version, parser_config_hash, ocsf_schema_version, payload_sha256.
- **Acceptance:** raw_event_id resolves to exactly one immutable raw record. Full lineage queryable in ClickHouse.
- **Tests:** T14

### FR-014: Duplicate Handling
- **ID:** FR-014
- **Priority:** MUST
- **Description:** Repeated events SHALL have deterministic identity behavior. Dedup only when explicitly configured.
- **Acceptance:** Same bytes = same hash; behavior per policy documented and reproducible.
- **Tests:** T15

### FR-015: Out-of-Order Events
- **ID:** FR-015
- **Priority:** MUST
- **Description:** Events with timestamps before/after arrival time SHALL be accepted. Both event_time and ingest_time SHALL be stored.
- **Acceptance:** Future and past timestamps accepted; both times queryable.
- **Tests:** T16

### FR-016: Quarantine/Dead-Letter Path
- **ID:** FR-016
- **Priority:** MUST
- **Description:** Failed or unsupported events SHALL enter a recoverable quarantine path. Quarantine SHALL retain raw_event_id reference.
- **Acceptance:** Quarantine directory has entries with raw_event_id, failure_type, error. Raw payload still retrievable.
- **Tests:** T17

### FR-017: ClickHouse Analytics Store
- **ID:** FR-017
- **Priority:** MUST
- **Description:** Normalized OCSF events SHALL be queryable in ClickHouse. Tables: raw_event_index, ocsf_events, processing_errors, ingestion_metrics.
- **Acceptance:** SQL queries return correct results; schema supports efficient filtering by type, time, source.
- **Tests:** (Integration)

### FR-018: CLI Commands
- **ID:** FR-018
- **Priority:** MUST
- **Description:** The system SHALL provide CLI commands: ingest, parse, replay, validate, benchmark, config validate, config test, dataset import, inspect.
- **Acceptance:** Each command is functional and documented.
- **Tests:** (E2E)

### FR-019: Prometheus Metrics
- **ID:** FR-019
- **Priority:** MUST
- **Description:** The system SHALL expose a /metrics endpoint with all required counters and histograms.
- **Acceptance:** Prometheus-compatible output; all metrics incrementing correctly.
- **Tests:** (Integration)

### FR-020: AI Configuration Harness
- **ID:** FR-020
- **Priority:** SHOULD
- **Description:** An optional AI harness SHALL produce parser/mapping configs from sample logs. Generated configs MUST pass tests before activation.
- **Acceptance:** Sample log → parser.yaml → validation → tests → activation. AI not required at runtime.
- **Tests:** T18

### FR-021: SIEM Export Adapters
- **ID:** FR-021
- **Priority:** MUST
- **Description:** The system SHALL implement OutputSink interface with ClickHouseSink, ParquetSink, JSONLExportSink, SyslogSink, HTTPJSONSink.
- **Acceptance:** Sink abstraction is clean; mock sinks demonstrate; HTTP/Syslog outputs demonstrate SIEM compatibility.
- **Tests:** (Integration)

### FR-022: Docker Compose Deployment
- **ID:** FR-022
- **Priority:** MUST
- **Description:** The full system SHALL be deployable via Docker Compose with services: ulpf, clickhouse, minio, dummy-firewall, dummy-router, dummy-linux, dummy-web, dummy-database, dummy-auth, dummy-ids.
- **Acceptance:** `docker compose up` starts all services; demo completes successfully.
- **Tests:** (E2E)

### FR-023: Air-Gapped Build
- **ID:** FR-023
- **Priority:** MUST
- **Description:** The system SHALL be buildable without Internet access. All dependencies vendored or cached. OCSF schema bundled.
- **Acceptance:** scripts/vendor.sh creates offline bundle; scripts/build-airgapped.sh succeeds on isolated machine.
- **Tests:** (E2E)

---

## 2. Non-Functional Requirements

### NFR-001: Raw Preservation Priority
- **Priority:** NON-NEGOTIABLE
- **Description:** Lossless preservation takes priority over all other concerns: parsing accuracy, speed, storage efficiency, and normalization.
- **Acceptance:** Any event whose raw bytes cannot be preserved must be rejected BEFORE the sender is acknowledged.

### NFR-002: Deterministic OCSF Validation
- **Priority:** MUST
- **Description:** OCSF validation MUST be deterministic across runs. Same event bytes must always produce the same validation result.
- **Acceptance:** Repeated validation of same event yields identical pass/fail and identical normalized output.

### NFR-003: No Runtime Internet Dependency
- **Priority:** MUST
- **Description:** Runtime operation MUST NOT require Internet access. No schema fetches, no API calls, no telemetry.
- **Acceptance:** System runs and processes events on an isolated host with no network connectivity.

### NFR-004: Air-Gapped Deployability
- **Priority:** MUST
- **Description:** The complete system MUST be deployable in an air-gapped Linux environment after initial dependency pre-fetch.
- **Acceptance:** Build scripts produce an offline-compatible package.

### NFR-005: Plugin Extensibility Without Core Changes
- **Priority:** MUST
- **Description:** New parsers and mappings MUST be addable through configuration/plugins without modifying the ingestion core.
- **Acceptance:** Demonstrated by adding a new source via YAML alone.

### NFR-006: AI Not Required at Runtime
- **Priority:** MUST
- **Description:** AI must never be a mandatory runtime dependency for deterministic log processing.
- **Acceptance:** System runs fully without any AI provider configured.

### NFR-007: TDD Discipline
- **Priority:** MUST
- **Description:** Tests MUST be written and demonstrated before implementation of the corresponding production component.
- **Acceptance:** Every production file has a corresponding test file written first.

### NFR-008: Laptop-Scale Performance
- **Priority:** MUST
- **Description:** The system MUST run on a Ryzen 5 5500H laptop with 16GB RAM. Benchmarks must use realistic local tiers.
- **Acceptance:** Tier 1-3 complete within reasonable time; Tier 4-5 demonstrate scaling without OOM.

### NFR-009: Bounded Memory
- **Priority:** MUST
- **Description:** Memory usage MUST remain bounded under sustained load and backpressure.
- **Acceptance:** Queue depth limits enforced; OOM never occurs under configured load.

### NFR-010: Sequential Disk Writes
- **Priority:** SHOULD
- **Description:** Spool and archive writes SHOULD be sequential to maximize SSD throughput.
- **Acceptance:** Write patterns verified; random I/O minimized.

### NFR-011: Crash Safety
- **Priority:** MUST
- **Description:** A crash midway through a write MUST be detectable and not corrupt durable data.
- **Acceptance:** CRC/checksum verification on spool replay; incomplete writes detected and handled.

### NFR-012: Configuration Validation at Startup
- **Priority:** MUST
- **Description:** Invalid configuration MUST fail at startup/validation time rather than corrupting data at runtime.
- **Acceptance:** T25 tests pass; bad config never reaches production processing.

---

## 3. Security Requirements

### SEC-001: No Arbitrary Code Execution
- **Description:** The system MUST NOT execute arbitrary input as code.
- **Acceptance:** No eval of log content; config does not embed executable code.

### SEC-002: Regex DoS Protection
- **Description:** Regex patterns MUST have enforced timeouts to prevent ReDoS.
- **Acceptance:** T24.3 passes; regex timeout configurable.

### SEC-003: Path Traversal Prevention
- **Description:** All file paths MUST be sanitized; no path traversal via config or input.
- **Acceptance:** Paths outside data/ directory are rejected.

### SEC-004: Oversized Payload Limits
- **Description:** Events exceeding configured max size MUST be rejected with raw preserved in quarantine.
- **Acceptance:** T23.6, T24.1 pass.

### SEC-005: Resource Exhaustion Prevention
- **Description:** Worker pools, queues, and connections MUST have explicit bounds.
- **Acceptance:** T21 passes; system degrades gracefully.

### SEC-006: Plugin Loading Safety
- **Description:** Plugin loading MUST be disabled by default; explicit allowlist required.
- **Acceptance:** No dynamic code loading without operator action.

---

## 4. Log Source Support Matrix

| Source Category | Formats | OCSF Target Classes | Phase |
|----------------|---------|---------------------|-------|
| Syslog | RFC 3164, RFC 5424 | Various | 6 |
| JSON | Structured JSON | Various | 6 |
| Apache/Nginx | Combined, custom | HTTP Activity | 6 |
| Firewall | Key=value, regex | Network Activity | 6 |
| Linux/SSH | Syslog-derived | Authentication, Process Activity | 7 |
| journald | JSON journal | Various | 3 |
| Database | PostgreSQL, MySQL logs | Authentication, Application Activity | 7 |
| Windows Event | JSON/XML export | Various | 6 |
| DNS | Various formats | DNS Activity | 7 |
| Application | JSON, text | Application Activity | 7 |

---

## 5. OCSF Schema Version

- **Pinned Version:** OCSF v1.8.0
- **Location:** third_party/ocsf-schema/
- **Runtime Access:** Local only — no network schema access
- **Upgrade Process:** Manual — download new release, update version reference, re-run validation

---

## 6. Platform Requirements

- **Runtime OS:** Linux (primary target)
- **Build OS:** Linux (development on Arch Linux)
- **Container Runtime:** Docker with Compose
- **Minimum Hardware:** Ryzen 5 5500H, 16GB RAM, SSD
- **Deployment Targets:** Single laptop (demo), Docker Compose (local), horizontal scaling (architectural)
