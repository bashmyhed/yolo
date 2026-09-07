# ULPF Architecture

**Universal Log Pre-processing Framework**  
**NTRO Problem Statement 26156**

---

## 1. Mission

Build a Linux-first framework that ingests heterogeneous logs from any source, preserves original bytes without information loss, parses and normalizes to strict OCSF, and exposes data to SIEM/analytics systems.

**Non-negotiable principles:** (1) Lossless preservation over speed/storage, (2) every event traceable to its raw bytes, (3) parser failures never destroy data, (4) fully air-gappable, (5) tests before implementation.

---

## 2. Data Flow

```
Local Sources (Files, Journald, Syslog)
        │
Network Sources (TCP, UDP, HTTP)
        │
Remote Pull Adapters (extensible SDK)
        │
        ▼
┌─────────────────────────────┐
│  Go Collector               │
│  Framing → Raw Creation    │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Durable Local Spool        │
│  Crash-safe / Replayable   │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Decoder → Parser           │
│  (config-driven)            │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│  Normalizer → OCSF Mapper  │
│  OCSF Validator (pinned)   │
└──┬─────────────────────┬───┘
   │                     │
   ▼                     ▼
Parquet Lake          ClickHouse
(authoritative)      (analytics)
   │
   ▼
SIEM / Wazuh
```

---

## 3. Core Components

**Collector (Go):** Ingests events from files, TCP, UDP, HTTP, journald, and pull adapters. Applies framing, generates raw_event_id (ULID), computes SHA-256, persists to spool before acknowledgment.

**Durable Local Spool:** Write-ahead-log-inspired disk spool. Sequential segment files with CRC32 checksums, fsync-on-close, bounded size, crash-replay from committed offsets. Exists to bridge ingestion and downstream processing without loss.

**Parquet Raw Archive:** Authoritative immutable storage. Partitioned by source_id/date/hour. Written once, never modified. Provides page-level predicate pushdown for efficient reads.

**ClickHouse Analytics Store:** Normalized OCSF events queryable via SQL. MergeTree parts are immutable on insert. Tables: raw_event_index, ocsf_events, processing_errors, ingestion_metrics.

**Parser Framework:** Config-driven (YAML). Extraction via regex, JSON path, delimiter, key=value, syslog fields. No core code changes for new sources.

**OCSF Mapper:** Separate from parsing. Maps parsed fields to pinned OCSF schema v1.8.0. Validates mappings at startup; invalid configs rejected before processing.

**Quarantine/Dead-Letter:** Failed events retain raw_event_id, failure_type, error, timestamp. Reference to immutable raw record always preserved.

**AI Harness (optional):** Offline tool that generates parser.yaml + mapping.yaml from sample logs. Generated configs tested before activation. Zero runtime AI dependency.

---

## 4. Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Core language | Go | Static binary, strong concurrency, mature ecosystem |
| Spool strategy | Spool-first durability | Downstream failures never cause loss |
| Raw archive | Immutable Parquet | Columnar compression, WORM alignment, S3-extensible |
| Analytics store | ClickHouse MergeTree | High insert rate, immutable parts, SQL |
| OCSF version | Pinned v1.8.0 | Deterministic validation, air-gap compatible |
| Parser model | Config-driven YAML | Zero core changes for new sources |
| AI position | Optional tool only | Air-gap compatibility; deterministic runtime |

---

## 5. Performance Tiers

| Tier | Events | Purpose |
|------|--------|---------|
| 1 | 10K | Correctness validation |
| 2 | 100K | Throughput baseline |
| 3 | 1M | Heavy load |
| 4 | 10M | Stress test |
| 5 | Sustained | Saturation point |

Metrics: events/sec, MB/sec, CPU%, RAM, disk throughput, P50/P95/P99 latency, error rate, storage amplification.

**Architecture is horizontally scalable.** Local benchmarks measure laptop limits; the design scales to billion-event/day via partitioning and distributed ClickHouse.

---

## 6. Security & Safety

- No arbitrary code execution via config or input
- Regex timeout enforcement (ReDoS protection)
- Bounded worker pools and queues
- Configurable max event size (default 64KB)
- Max JSON nesting depth enforced
- Plugin loading disabled by default
- Path traversal prevention

---

## 7. Air-Gapped Deployment

```bash
# Online machine
./scripts/vendor.sh          # Cache Go modules + Docker images
tar -czf ulpf-offline.tar.gz ulpf/

# Air-gapped machine
tar -xzf ulpf-offline.tar.gz
./scripts/build-airgapped.sh
./scripts/verify-offline.sh
docker compose up
```

Runtime depends on: nothing external. OCSF schema bundled, dependencies vendored.

---

## 8. Deliverables

1. GitHub-ready source tree
2. Docker Compose environment
3. Test suite (25 test families, ~80 cases)
4. Benchmark results (Tier 1-5)
5. LogHub dataset import scripts
6. AI config generator
7. SIEM output adapters (ClickHouse, Parquet, JSONL, Syslog, HTTP)
8. Parser configuration examples
9. Demo: end-to-end with dummy sources + quarantine + AI harness

---

**Author:** Pranoy Paul, B.Tech CSE, BPPIMT Kolkata  
**Repository:** github.com/bashmyhed/ulpf  
**OCSF Schema:** v1.8.0 (pinned)
