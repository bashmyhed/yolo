# ULPF Benchmark Methodology

**Version:** 1.0.0  
**Date:** 2026-09-07  
**Author:** Pranoy Paul

---

## 1. Benchmark Philosophy

Benchmarks measure **what the system can do locally** — not fabricated enterprise-scale claims. Results are reproducible on a Ryzen 5 5500H / 16GB RAM laptop.

We establish local **tiers** rather than extrapolating to billions of events/day. The goal is to demonstrate:
1. Correct operation at each scale
2. Where bottlenecks appear
3. That the architecture can scale horizontally (design, not local proof)

---

## 2. Benchmark Tiers

| Tier | Events | Purpose | Target Wall Time |
|------|--------|---------|------------------|
| Tier 1 | 10,000 | Smoke test; correctness validation | < 10s |
| Tier 2 | 100,000 | Moderate load; throughput baseline | < 60s |
| Tier 3 | 1,000,0000 | Heavy load; resource monitoring | < 10 min |
| Tier 4 | 10,000,000 | Stress test; scaling observation | < 60 min |
| Tier 5 | Sustained | Find saturation point | Until saturation |

**Note:** These are targets for the initial implementation. Actual results will vary by hardware, configuration, and event complexity.

---

## 3. Metrics Collection

### 3.1 Throughput Metrics
| Metric | Unit | Collection Method |
|--------|------|-------------------|
| events/sec | events/second | Counter delta / wall time |
| bytes/sec | bytes/second | Byte counter delta / wall time |
| parse_latency | milliseconds | Histogram (P50, P95, P99) |
| normalize_latency | milliseconds | Histogram (P50, P95, P99) |
| end_to_end_latency | milliseconds | Histogram (P50, P95, P99) |

### 3.2 Resource Metrics
| Metric | Unit | Collection Method |
|--------|------|-------------------|
| CPU utilization | % | OS-level sampling during benchmark |
| RAM usage | MB | Go runtime.ReadMemStats + OS |
| disk_write_rate | MB/s | OS-level disk stats |
| disk_usage | GB | Post-benchmark directory size |
| disk_io_utilization | % | iostat during benchmark |
| goroutine_count | count | runtime.NumGoroutine |

### 3.3 Quality Metrics
| Metric | Unit | Collection Method |
|--------|------|-------------------|
| error_rate | % | errors / total * 100 |
| quarantine_rate | % | quarantined / total * 100 |
| duplicate_rate | % | duplicates / total * 100 |
| storage_amplification | ratio | disk_bytes / raw_bytes |

### 3.4 Pipeline Metrics
| Metric | Unit | Collection Method |
|--------|------|-------------------|
| queue_depth | count | Channel length / Prometheus gauge |
| spool_bytes | bytes | Spool directory size |
| active_parsers | count | Goroutine pool status |
| batch_insert_latency | ms | ClickHouse sink histogram |

---

## 4. Benchmark Harness

### 4.1 Synthetic Generator
A Go-based synthetic log generator produces events with configurable:
- Rate (events/sec)
- Burst size
- Format (syslog, JSON, Apache, key=value, etc.)
- Size (1KB to 1MB per event)
- Seed (deterministic reproducibility)

### 4.2 Real Datasets
LogHub datasets for representative real-world structure:
- HDFS_v1 (~11M lines)
- Linux (~540K lines)
- Others available for extended testing

### 4.3 Transport
Events delivered over TCP to the collector (except file-based tests which use file ingestion).

### 4.4 Collector Configuration
- Default worker pool size
- Default queue depth
- Default batch sizes
- No special tuning for benchmarks — reflect "out of box" performance

---

## 5. Benchmark Execution

### 5.1 Pre-flight Checks
```
1. System idle (no other heavy processes)
2. Disk space available (>5x expected dataset size)
3. ClickHouse container running (if testing ClickHouse sink)
4. ulpf binary built in release mode
```

### 5.2 Run Protocol
```bash
# For each tier:
# 1. Start ulpf collector
ulpf ingest --config configs/benchmark.yaml &

# 2. Wait for collector ready
sleep 2

# 3. Start benchmark client
ulpf benchmark --tier 1 --format syslog --seed 42

# 4. Collect metrics from /metrics endpoint
curl -s http://localhost:9090/metrics > results/tier1_metrics.txt

# 5. Record system metrics
# 6. Stop collector
# 7. Verify: event count, raw archive completeness, ClickHouse row count
```

### 5.3 Data Collection
```
results/
  tier1/
    metrics.txt          # Prometheus scrape
    summary.json         # Parsed summary
    events_per_sec.json  # Time-series throughput
    sysstat.log          # iostat/vmstat/sar output
  tier2/
    ...
```

---

## 6. Reporting Format

### 6.1 Per-Tier Summary Table
```
| Metric | Tier 1 (10K) | Tier 2 (100K) | Tier 3 (1M) | Tier 4 (10M) |
|--------|--------------|---------------|-------------|--------------|
| events/sec | ... | ... | ... | ... |
| MB/sec | ... | ... | ... | ... |
| CPU % | ... | ... | ... | ... |
| RAM MB | ... | ... | ... | ... |
| P50 latency ms | ... | ... | ... | ... |
| P95 latency ms | ... | ... | ... | ... |
| P99 latency ms | ... | ... | ... | ... |
| error_rate % | ... | ... | ... | ... |
| disk usage MB | ... | ... | ... | ... |
| storage_amp | ... | ... | ... | ... |
```

### 6.2 Scaling Chart
Plot events/sec vs tier to identify linear scaling region and saturation point.

### 6.3 Resource Plot
Plot CPU, RAM, and disk write rate over time during Tier 5 sustained run.

---

## 7. Expected Results (Placeholder)

| Metric | Expected Range | Notes |
|--------|---------------|-------|
| Tier 1 events/sec | 5,000 - 50,000 | Laptop SSD bound |
| Tier 2 events/sec | 10,000 - 80,000 | Memory bandwidth bound |
| Tier 3 events/sec | 15,000 - 100,000 | Sustained throughput |
| Parse_latency P50 | < 1ms | Per event |
| Parse_latency P95 | < 5ms | Per event |
| Parse_latency P99 | < 20ms | Per event |
| error_rate | 0% | No silent loss |
| quarantine_rate | < 5% | For adversarial tests |
| storage_amplification | 2x-4x | Raw + normalized + metadata |

**Note:** These are pre-implementation estimates. Actual results will be recorded during Phase 10.

---

## 8. Reproducibility Requirements

- Same seed for synthetic generation
- Same collector configuration
- Same dataset version
- Same hardware (laptop)
- Document any system load during test
- Report Go version, kernel version, Docker version

---

## 9. What We Do NOT Claim

- Billions of events/day on a laptop (physically impossible)
- Zero-loss on UDP (transport-level loss)
- Linear scaling beyond local hardware
- Sub-millisecond P99 for 1MB+ events (I/O bound)

Instead we demonstrate:
- Lossless preservation (proven by byte comparison)
- Crash recovery (proven by restart tests)
- Backpressure behavior (proven by slow-consumer tests)
- Horizontal scalability (proven by architecture design)

---

## 10. Benchmark Tools

- `ulpf benchmark` — built-in benchmark command
- `ulpf dataset import` — import LogHub datasets
- Prometheus `/metrics` — live system metrics
- `iostat`, `vmstat` — OS-level resource monitoring
- Go `testing.B` — micro-benchmarks for parser components
