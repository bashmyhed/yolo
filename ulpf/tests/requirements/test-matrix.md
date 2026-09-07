# ULPF Test Matrix

**Version:** 1.0.0
**OCSF Schema:** v1.8.0 (pinned)
**Date:** 2026-09-07
**Author:** Pranoy Paul

---

## Test Matrix Conventions

Each test has:
- **ID**: Unique test family identifier
- **Description**: What is being verified
- **Input**: Test data/conditions
- **Expected Behavior**: Observable correct behavior
- **Expected Output**: Concrete artifact/state
- **Failure Condition**: What constitutes a test failure

Tests are executed **before** implementation of the corresponding production component (TDD discipline).

---

## T01: Raw Preservation

### T01.1: UTF-8 preservation
- **Description**: UTF-8 encoded bytes must survive ingestion unchanged
- **Input**: Byte sequence containing multi-byte UTF-8 characters (e.g., "Hello 世界 🌡️")
- **Expected Behavior**: Persisted raw bytes match input exactly
- **Expected Output**: `sha256(persisted) == sha256(input)`
- **Failure Condition**: Any byte differs; encoding changes detected

### T01.2: Non-UTF-8 bytes preservation
- **Description**: Invalid UTF-8 byte sequences must be preserved
- **Input**: Bytes `[0xFF, 0xFE, 0x00, 0x01, 0xC0, 0xC1]`
- **Expected Behavior**: Raw bytes stored verbatim, no replacement characters
- **Expected Output**: Byte-for-byte match with input
- **Failure Condition**: Bytes replaced, stripped, or coerced

### T01.3: Null byte preservation
- **Description**: Null bytes must not be treated as string terminators
- **Input**: `b"before\x00after\x00\x00end"`
- **Expected Behavior**: All bytes including nulls persisted
- **Expected Output**: Length matches input; every byte retrievable
- **Failure Condition**: Truncation at first null; length mismatch

### T01.4: Escaped characters preservation
- **Description**: Escape sequences preserved as literal bytes
- **Input**: `b"\\n\\t\\r\\\"\\\\"` (literal backslash-n, backslash-t, etc.)
- **Expected Behavior**: No unescaping performed
- **Expected Output**: Raw bytes identical to input
- **Failure Condition**: Escapes interpreted/unescaped

### T01.5: Tab and newline preservation
- **Description**: Whitespace-sensitive payloads preserved exactly
- **Input**: `"col1\tcol2\tcol3\nline2\tval\tend\n"`
- **Expected Behavior**: Tabs and newlines intact
- **Expected Output**: Exact byte match
- **Failure Condition**: Whitespace altered

### T01.6: Multi-line payload preservation
- **Description**: Events spanning multiple lines preserved
- **Input**: Stack trace or multi-line log with `\n` and `\r\n`
- **Expected Behavior**: Line endings preserved exactly
- **Expected Output**: Byte-for-byte match
- **Failure Condition**: Lines merged or endings normalized

### T01.7: Very long field preservation
- **Description**: Large field values not truncated
- **Input**: Single field with 1MB+ of text
- **Expected Behavior**: Complete field preserved
- **Expected Output**: Size match; hash match
- **Failure Condition**: Truncation, silent size limit

### T01.8: Malformed JSON preservation
- **Description**: Invalid JSON stored as-is
- **Input**: `{"broken": true, missing_quote: value}`
- **Expected Behavior**: Parse failure does not prevent raw storage
- **Expected Output**: Raw bytes persisted; parse error recorded separately
- **Failure Condition**: Raw bytes discarded on parse failure

### T01.9: Binary-looking payload preservation
- **Description**: Non-text bytes preserved
- **Input**: `[0x00-0xFF]` all 256 byte values
- **Expected Behavior**: No bytes rejected for being non-text
- **Expected Output**: All 256 bytes retrievable
- **Failure Condition**: Binary bytes filtered, escaped, or lost

---

## T02: TCP Ingestion

### T02.1: Basic connection handling
- **Description**: TCP listener accepts connections
- **Input**: Single TCP client connects and sends one message
- **Expected Behavior**: Connection accepted; message received
- **Expected Output**: Event ingested and durable
- **Failure Condition**: Connection refused; message lost

### T02.2: Message framing
- **Description**: Correct message boundaries detected
- **Input**: Multiple messages sent in single TCP segment
- **Expected Behavior**: Each message framed correctly (length-prefixed or delimiter-based)
- **Expected Output**: Correct number of events, correct boundaries
- **Failure Condition**: Messages concatenated or split incorrectly

### T02.3: Sustained ingestion
- **Description**: Long-running TCP connection
- **Input**: Client sends 10,000 events over persistent connection
- **Expected Behavior**: All events ingested without loss
- **Expected Output**: Count matches; hashes match
- **Failure Condition**: Event loss; connection drop

### T02.4: Reconnects
- **Description**: Client disconnects and reconnects
- **Input**: Client sends events, disconnects, reconnects, sends more
- **Expected Behavior**: Both batches ingested; no state corruption
- **Expected Output**: All events from both connections
- **Failure Condition**: Second connection fails; state corruption

### T02.5: Partial writes
- **Description**: Message sent in multiple small writes
- **Input**: Single message split across 10 TCP writes
- **Expected Behavior**: Framing reassembles correctly
- **Expected Output**: Single complete event
- **Failure Condition**: Partial message treated as complete

### T02.6: Sender disconnect
- **Description**: Client disconnects mid-transmission
- **Input**: Client sends partial message then disconnects
- **Expected Behavior**: Partial data handled gracefully
- **Expected Output**: Complete messages ingested; partial handled per policy
- **Failure Condition**: Crash; data corruption

### T02.7: Multiple concurrent clients
- **Description**: Multiple simultaneous TCP connections
- **Input**: 10 clients each sending 1000 events concurrently
- **Expected Behavior**: All events from all clients ingested
- **Expected Output**: 10,000 events total; correct attribution
- **Failure Condition**: Event loss; cross-client contamination

### T02.8: Backpressure
- **Description**: Slow consumer triggers backpressure
- **Input**: High-rate input with delayed downstream processing
- **Expected Behavior**: Memory bounded; no OOM
- **Expected Output**: Backpressure signals propagate; no event loss
- **Failure Condition**: Unbounded memory growth; OOM crash

---

## T03: Syslog

### T03.1: RFC 3164 (BSD syslog)
- **Description**: Parse traditional BSD syslog format
- **Input**: `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`
- **Expected Behavior**: Priority, timestamp, hostname, tag, content extracted
- **Expected Output**: Structured fields populated correctly
- **Failure Condition**: Parse failure on valid RFC 3164

### T03.2: RFC 5424
- **Description**: Parse structured syslog (RFC 5424)
- **Input**: `<165>1 2023-10-11T22:14:15.003Z mymachine evntslog - - - [exampleSDID@32473 iut="3"] An event`
- **Expected Behavior**: All structured data elements parsed
- **Expected Output**: Structured fields + SD elements
- **Failure Condition**: Parse failure on valid RFC 5424

### T03.3: Malformed syslog
- **Description**: Invalid syslog handled gracefully
- **Input`: `not a syslog message at all`
- **Expected Behavior**: Raw preserved; parse error recorded
- **Expected Output**: Event in quarantine with raw copy
- **Failure Condition**: Raw discarded

### T03.4: Missing fields
- **Description**: Syslog with missing optional fields
- **Input`: `<13>Oct 11 22:14:15 host msg` (no tag/structure)
- **Expected Behavior**: Parsed with available fields
- **Expected Output**: Available fields populated; absent fields null
- **Failure Condition**: Rejection due to missing optional fields

### T03.5: Invalid timestamps
- **Description**: Syslog with unparseable timestamp
- **Input`: `<13>BROKEN_TIMESTAMP host tag: message`
- **Expected Behavior**: Raw preserved; parse continues
- **Expected Output**: Timestamp field null or best-effort; event not rejected
- **Failure Condition**: Event rejected for bad timestamp

### T03.6: Oversized syslog messages
- **Description**: Message exceeding typical MTU
- **Input`: Syslog message > 64KB
- **Expected Behavior**: Handled per configured max message size
- **Expected Output**: Either parsed or cleanly rejected; raw preserved
- **Failure Condition**: Crash; silent truncation

---

## T04: JSON

### T04.1: Valid JSON
- **Description**: Parse well-formed JSON event
- **Input**: `{"timestamp":"2023-01-01T00:00:00Z","src_ip":"10.0.0.1","action":"allow"}`
- **Expected Behavior**: All fields extracted
- **Expected Output**: Structured representation matches input
- **Failure Condition**: Parse failure

### T04.2: Nested JSON
- **Description**: Parse deeply nested structures
- **Input**: `{"a":{"b":{"c":{"d":"value"}}}}`
- **Expected Behavior**: Nested accessors resolve correctly
- **Expected Output**: Path `a.b.c.d` returns `"value"`
- **Failure Condition**: Nesting not supported

### T04.3: Malformed JSON
- **Description**: Invalid JSON preserved
- **Input**: `{broken json,}`
- **Expected Behavior**: Raw stored; parse error recorded
- **Expected Output**: Quarantine entry with raw bytes
- **Failure Condition**: Raw discarded

### T04.4: Additional fields
- **Description**: Extra unmapped fields preserved
- **Input**: JSON with fields not in any mapping
- **Expected Behavior**: Known fields mapped; unknown fields preserved in metadata
- **Expected Output**: Mapped fields in OCSF; raw retains all original fields
- **Failure Condition**: Unknown fields cause rejection

### T04.5: JSON arrays
- **Description**: Top-level JSON arrays handled
- **Input**: `[{}, {}, {}]`
- **Expected Behavior**: Each element treated as separate event OR handled per policy
- **Expected Output**: Deterministic behavior documented
- **Failure Condition**: Undefined behavior

### T04.6: Null values
- **Description**: Null values handled
- **Input**: `{"field": null}`
- **Expected Behavior**: Field recognized but null
- **Expected Output**: Field present with null value
- **Failure Condition**: Null causes rejection

### T04.7: Duplicate fields
- **Description**: Duplicate keys in JSON
- **Input**: `{"key":"val1","key":"val2"}`
- **Expected Behavior**: Behavior deterministic (last wins, first wins, or error)
- **Expected Output**: Documented behavior applied consistently
- **Failure Condition**: Non-deterministic behavior

---

## T05: File Ingestion

### T05.1: Append-only log file
- **Description**: Tail and ingest growing file
- **Input**: File appended to while collector is running
- **Expected Behavior**: New lines ingested as they appear
- **Expected Output**: All lines eventually ingested
- **Failure Condition**: Lines missed; offset corruption

### T05.2: File rotation (copytruncate)
- **Description**: File truncated in place (common logrotate strategy)
- **Input**: Collector reading file that gets truncated
- **Expected Behavior**: Detect truncation; re-read from start or handle gracefully
- **Expected Output**: No duplicate ingestion or missed events
- **Failure Condition**: Duplicate or lost events

### T05.3: Rename rotation
- **Description**: File moved and new file created (logrotate default)
- **Input**: Collector reading file that gets renamed; new file created at same path
- **Expected Behavior**: Detect inode change; open new file
- **Expected Output**: Events from both old and new files ingested
- **Failure Condition**: Stops ingesting after rotation

### T05.4: File deletion
- **Description**: File removed while being read
- **Input**: Collector reading file that gets deleted
- **Expected Behavior**: Handle gracefully; continue watching directory
- **Expected Output**: No crash; file state cleaned up
- **Failure Condition**: Crash; resource leak

### T05.5: Restart recovery
- **Description**: Collector restarts mid-file
- **Input**: Collector stopped at offset X; restarted
- **Expected Behavior**: Resume from last committed offset
- **Expected Output**: No re-ingestion of already-processed lines (or at most idempotent)
- **Failure Condition**: Full re-ingestion (if offset committed); lost events

### T05.6: Partial final line
- **Description**: File ends without newline
- **Input**: File with content `"complete line\nincomplete line"`
- **Expected Behavior**: Partial line buffered or handled per policy
- **Expected Output**: Complete line ingested; partial handled deterministically
- **Failure Condition**: Partial line lost

---

## T06: Journald Ingestion

### T06.1: System journal collection
- **Description**: Read from systemd journal
- **Input**: `journalctl --output=json` style entries
- **Expected Behavior**: Journal entries parsed and ingested
- **Expected Output**: All journal fields preserved
- **Failure Condition**: Collection failure

### T06.2: Journal following
- **Description**: Follow journal for new entries
- **Input**: Continuous `sd_journal_next` loop
- **Expected Behavior**: New entries ingested in real-time
- **Expected Output**: Low-latency ingestion of new entries
- **Failure Condition**: Lag or missed entries

### T06.3: Journal cursor recovery
- **Description**: Resume from saved cursor
- **Input**: Collector restart after cursor saved
- **Expected Behavior**: Resume from last cursor position
- **Expected Output**: No missed or duplicate entries
- **Failure Condition**: Duplicate or missed entries

---

## T07: Network-Device Events

### T07.1: Firewall allow event
- **Description**: Parse firewall permit log
- **Input**: Synthetic firewall allow event
- **Expected Behavior**: Mapped to Network Activity OCSF class
- **Expected Output**: src_endpoint, dst_endpoint, action=allowed
- **Failure Condition**: Parse or mapping failure

### T07.2: Firewall deny event
- **Description**: Parse firewall deny log
- **Input**: Synthetic firewall deny event
- **Expected Behavior**: Mapped to Network Activity OCSF class
- **Expected Output**: action=blocked
- **Failure Condition**: Parse or mapping failure

### T07.3: NAT event
- **Description**: Parse NAT translation log
- **Input**: NAT event with translated addresses
- **Expected Behavior**: Both original and translated addresses preserved
- **Expected Output**: src_endpoint and nat fields populated
- **Failure Condition**: Address information lost

### T07.4: IDS alert
- **Description**: Parse IDS/IPS alert
- **Input**: Suricata/Snort-style alert
- **Expected Behavior**: Mapped to Security Finding or Network Activity
- **Expected Output**: Signature, classification, endpoints present
- **Failure Condition**: Alert details lost

### T07.5: VPN event
- **Description**: Parse VPN connection event
- **Input**: VPN connect/disconnect log
- **Expected Behavior**: Mapped to appropriate OCSF class
- **Expected Output**: User, endpoint, tunnel info preserved
- **Failure Condition**: VPN-specific data lost

### T07.6: Authentication event
- **Description**: Parse network device authentication
- **Input**: Login success/failure on switch/router
- **Expected Behavior**: Mapped to Authentication OCSF class
- **Expected Output**: User, result, src_endpoint present
- **Failure Condition**: Auth event misclassified

### T07.7: DNS query event
- **Description**: Parse DNS query log
- **Input**: DNS resolver query log
- **Expected Behavior**: Mapped to DNS Activity OCSF class
- **Expected Output**: Query, response, status present
- **Failure Condition**: DNS data lost

### T07.8: DHCP event
- **Description**: Parse DHCP lease event
- **Input**: DHCP assign/release log
- **Expected Behavior**: Mapped to Network Activity
- **Expected Output**: IP, MAC, lease action present
- **Failure Condition**: DHCP data lost

### T07.9: Routing event
- **Description**: Parse routing protocol event
- **Input**: OSPF/BGP state change log
- **Expected Behavior**: Mapped to appropriate OCSF class
- **Expected Output**: Protocol, state, endpoints present
- **Failure Condition**: Routing data lost

---

## T08: Linux Server Events

### T08.1: SSH login
- **Description**: Parse SSH authentication success
- **Input**: `Accepted publickey for user from 192.168.1.1 port 22 ssh2`
- **Expected Behavior**: Mapped to Authentication OCSF class
- **Expected Output**: User, src_endpoint, auth type, result
- **Failure Condition**: Auth event lost

### T08.2: Sudo execution
- **Description**: Parse sudo command execution
- **Input**: `user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls`
- **Expected Behavior**: Mapped to Process Activity or Authorization
- **Expected Output**: User, command, target user present
- **Failure Condition**: sudo event lost

### T08.3: Process execution
- **Description**: Parse process execution (execve audit)
- **Input**: `type=SYSCALL msg=audit(1234567890.123:12345): arch=c000003e syscall=59 ...`
- **Expected Behavior**: Mapped to Process Activity
- **Expected Output**: PID, UID, command, arguments present
- **Failure Condition**: Process event lost

### T08.4: Authentication failure
- **Description**: Parse failed login
- **Input**: `Failed password for invalid user admin from 10.0.0.1 port 22`
- **Expected Behavior**: Mapped to Authentication with failure result
- **Expected Output**: Result=failure, attempted user present
- **Failure Condition**: Failure event lost

### T08.5: Service start/stop
- **Description**: Parse systemd service events
- **Input**: `Started/Stopped Some Service`
- **Expected Behavior**: Mapped to Application Activity or System Activity
- **Expected Output**: Service name, action, status present
- **Failure Condition**: Service event lost

### T08.6: Filesystem event
- **Description**: Parse file access/change (auditd)
- **Input**: `type=PATH msg=audit(...): item=0 name="/etc/passwd" ...`
- **Expected Behavior**: Mapped to File System Activity
- **Expected Output**: File path, action, actor present
- **Failure Condition**: File event lost

### T08.7: Kernel message
- **Description**: Parse kernel log message
- **Input**: `kernel: [12345.678] some kernel message`
- **Expected Behavior**: Mapped to System Activity or best-fit
- **Expected Output**: Message content preserved; classification best-effort
- **Failure Condition**: Message lost or misclassified

---

## T09: Application Logs

### T09.1: HTTP access log
- **Description**: Parse Apache/Nginx access log
- **Input**: `127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 2326`
- **Expected Behavior**: Mapped to HTTP Activity OCSF class
- **Expected Output**: Method, URL, status, bytes present
- **Failure Condition**: HTTP data lost

### T09.2: Application error
- **Description**: Parse structured error log
- **Input**: `{"level":"error","msg":"Connection refused","ts":"...","service":"api"}`
- **Expected Behavior**: Mapped to Application Activity
- **Expected Output**: Error details, service, severity present
- **Failure Condition**: Error data lost

### T09.3: Stack trace
- **Description**: Multi-line stack trace preserved
- **Input**: Java/Python stack trace with multiple lines
- **Expected Behavior**: Stack trace preserved as single event or coherent group
- **Expected Output**: All stack trace lines present and retrievable
- **Failure Condition**: Stack trace split into multiple unrelated events

### T09.4: Structured JSON application log
- **Description**: Parse application JSON log
- **Input**: `{"@timestamp":"...","logger":"...","level":"...","message":"..."}`
- **Expected Behavior**: Mapped to Application Activity
- **Expected Output**: Structured fields mapped to OCSF
- **Failure Condition**: Parse failure

### T09.5: Unstructured text
- **Description**: Free-form text log
- **Input**: `Something happened at 3pm and it was bad`
- **Expected Behavior**: Best-effort parsing; raw always preserved
- **Expected Output**: Minimal OCSF mapping; full raw in archive
- **Failure Condition**: Event discarded

---

## T10: Database Logs

### T10.1: Database authentication
- **Description**: Parse DB connection auth event
- **Input**: PostgreSQL `connection authorized` log
- **Expected Behavior**: Mapped to Authentication OCSF class
- **Expected Output**: User, database, source IP present
- **Failure Condition**: Auth event lost

### T10.2: Query log
- **Description**: Parse executed query
- **Input**: PostgreSQL `duration: 123.456 ms  statement: SELECT ...`
- **Expected Behavior**: Mapped to Application Activity or Database Activity
- **Expected Output**: Query text, duration, user present
- **Failure Condition**: Query data lost

### T10.3: Database failure
- **Description**: Parse DB error/failure
- **Input**: `FATAL: password authentication failed for user "admin"`
- **Expected Behavior**: Mapped to Application Activity with error
- **Expected Output**: Error type, user, database present
- **Failure Condition**: Error event lost

### T10.4: Connection event
- **Description**: Parse DB connection open/close
- **Input**: `connection received: host=10.0.0.1 port=5432`
- **Expected Behavior**: Mapped to Authentication or Network Activity
- **Expected Output**: Endpoint info, database present
- **Failure Condition**: Connection event lost

### T10.5: Privilege event
- **Description**: Parse GRANT/REVOKE or permission change
- **Input**: `GRANT SELECT ON table TO user`
- **Expected Behavior**: Mapped to Authorization or Authentication
- **Expected Output**: Privilege change details present
- **Failure Condition**: Privilege data lost

---

## T11: Windows-Style Logs

### T11.1: Windows Event Log (XML/JSON)
- **Description**: Parse Windows event format
- **Input**: Windows Event Log JSON export format
- **Expected Behavior**: Mapped to appropriate OCSF class
- **Expected Output**: Event ID, provider, fields mapped
- **Failure Condition**: Parse failure

### T11.2: Windows authentication event
- **Description**: Parse Windows login event (4624)
- **Input**: Windows Security event 4624
- **Expected Behavior**: Mapped to Authentication OCSF class
- **Expected Output**: User, logon type, source IP present
- **Failure Condition**: Auth data lost

### T11.3: Windows process creation
- **Description**: Parse Windows process creation (4688)
- **Input**: Windows Security event 4688
- **Expected Behavior**: Mapped to Process Activity
- **Expected Output**: Process, command line, parent present
- **Failure Condition**: Process data lost

---

## T12: LogHub Datasets

### T12.1: HDFS_v1 import
- **Description**: Ingest HDFS_v1 LogHub dataset
- **Input**: datasets/loghub/HDFS_v1/HDFS_v1.log
- **Expected Behavior**: Stream-process without full RAM load
- **Expected Output**: Events parsed; raw archived; metrics recorded
- **Failure Condition**: OOM; parse failure on valid data

### T12.2: Linux LogHub import
- **Description**: Ingest Linux LogHub dataset
- **Input**: datasets/loghub/Linux/Linux.log
- **Expected Behavior**: Stream-process correctly
- **Expected Output**: Events parsed per Linux parser
- **Failure Condition**: Parse failure

### T12.3: citation preservation
- **Description**: LogHub citation/license preserved
- **Input**: N/A
- **Expected Behavior**: Third-party/citation file present and complete
- **Expected Output**: Citation file exists and unchanged
- **Failure Condition**: Citation missing or modified

---

## T13: Parser Configuration

### T13.1: Add parser via config
- **Description**: New source onboarded via YAML only
- **Input**: New parser.yaml + mapping.yaml files
- **Expected Behavior**: No core code changes; system loads new parser at startup
- **Expected Output**: Events from new source parsed correctly
- **Failure Condition**: Core code modification required

### T13.2: Hot-reload validation
- **Description**: Config reload validates before activation
- **Input**: Updated parser configuration
- **Expected Behavior**: Validation passes before old config replaced
- **Expected Output**: New config active; old config available for rollback
- **Failure Condition**: Invalid config accepted; data corruption

---

## T14: Traceability

### T14.1: raw_event_id resolution
- **Description**: OCSF event links to exactly one raw event
- **Input**: Any ingested event
- **Expected Behavior**: `ocsf_event.raw_event_id` resolves to one immutable raw record
- **Expected Output**: Raw record retrievable by ID
- **Failure Condition**: ID resolves to zero or multiple records

### T14.2: Parser lineage recorded
- **Description**: Parser version/config hash stored
- **Input**: Event processed by specific parser version
- **Expected Output**: `parser_version`, `parser_config_hash`, `ocsf_schema_version` present
- **Failure Condition**: Lineage fields missing

### T14.3: SHA-256 integrity
- **Description**: Raw payload hash verifies integrity
- **Input**: Stored raw event
- **Expected Behavior**: Recomputed hash matches stored hash
- **Expected Output**: `sha256(payload) == stored_hash`
- **Failure Condition**: Hash mismatch

---

## T15: Duplicate Handling

### T15.1: Deterministic duplicate identity
- **Description**: Same bytes produce same identity
- **Input**: Two copies of identical event bytes
- **Expected Behavior**: Same content hash; behavior per policy (dedup or allow)
- **Expected Output**: Deterministic outcome documented and reproducible
- **Failure Condition**: Non-deterministic dedup behavior

### T15.2: Policy-based dedup
- **Description**: Configured dedup policy applied
- **Input**: Duplicate events with dedup policy=enabled
- **Expected Behavior**: Second copy handled per policy (skip/quarantine/normalize)
- **Expected Output**: Consistent with policy
- **Failure Condition**: Policy ignored

---

## T16: Out-of-Order Events

### T16.1: Event time vs ingest time
- **Description**: Both timestamps preserved independently
- **Input**: Event with timestamp in the past
- **Expected Behavior**: `event_time` = original timestamp; `ingest_time` = arrival time
- **Expected Output**: Both times recorded correctly
- **Failure Condition**: Times conflated or overwritten

### T16.2: Future timestamp
- **Description**: Event with future timestamp
- **Input**: Event with timestamp 1 hour in the future
- **Expected Behavior**: Accepted; no rejection for being future-dated
- **Expected Output**: Both times recorded; event ingested
- **Failure Condition**: Future-dated events rejected

---

## T17: Parser Failure

### T17.1: Failed event has raw copy
- **Description**: Parse failure preserves raw bytes
- **Input**: Event that fails parsing
- **Expected Behavior**: Raw stored before parse attempt; never destroyed on failure
- **Expected Output**: Raw record exists with correct payload
- **Failure Condition**: Raw lost on parse failure

### T17.2: Failed event has metadata
- **Description**: Failed events still get IDs and metadata
- **Input**: Event that fails parsing
- **Expected Behavior**: raw_event_id, source_id, received_at all present
- **Expected Output**: Metadata complete even on failure
- **Failure Condition**: Metadata missing for failed events

### T17.3: Failure reason recorded
- **Description**: Quarantine entry explains why
- **Input**: Event that fails parsing
- **Expected Behavior**: failure_type, error message recorded
- **Expected Output**: Quarantine record has failure details
- **Failure Condition**: No failure reason available

---

## T18: OCSF Validation

### T18.1: Valid OCSF passes
- **Description**: Conforming event validates
- **Input**: Properly mapped OCSF event
- **Expected Behavior**: Schema validation passes
- **Expected Output**: Event accepted into ClickHouse
- **Failure Condition**: Valid event rejected

### T18.2: Invalid OCSF rejected
- **Description**: Non-conforming event rejected
- **Input**: OCSF event missing required field
- **Expected Behavior**: Schema validation fails; event sent to quarantine
- **Expected Output**: Event not in ClickHouse; in quarantine
- **Failure Condition**: Invalid event accepted

### T18.3: Pinned schema version
- **Description**: Schema version is stable
- **Input**: Any event
- **Expected Behavior**: Schema version is pinned release (v1.8.x), not "latest"
- **Expected Output**: Schema version explicitly recorded
- **Failure Condition**: Unversioned schema; runtime schema fetch

---

## T19: Restart Recovery

### T19.1: Clean shutdown recovery
- **Description**: Graceful restart preserves all events
- **Input**: Ingestion running; SIGTERM issued; restart
- **Expected Behavior**: All durable events recovered; no loss
- **Expected Output**: Event count matches pre-shutdown
- **Failure Condition**: Events lost during clean restart

### T19.2: Crash recovery
- **Description**: Simulated crash (SIGKILL) preserves durable events
- **Input**: Ingestion running; SIGKILL; restart
- **Expected Behavior**: Events durably spooled before crash recovered
- **Expected Output**: No silent loss region
- **Failure Condition**: Silent data loss beyond acknowledged durability window

---

## T20: Disk-Full Behavior

### T20.1: Full spool stops durable claims
- **Description**: System stops acknowledging when disk full
- **Input**: Spool partition fills up
- **Expected Behavior**: No new durable acknowledgments; failure exposed
- **Expected Output**: Events not acknowledged; error metrics increment
- **Failure Condition**: Silent drops; false acknowledgments

### T20.2: Ordering preserved under disk pressure
- **Description**: Event ordering maintained when storage constrained
- **Input**: Disk full condition; events continue arriving
- **Expected Behavior**: In-memory queue or upstream backpressure; ordering not violated
- **Expected Output**: Events remain ordered by arrival
- **Failure Condition**: Out-of-order due to disk pressure

### T20.3: Error exposed on disk full
- **Description**: Operators can detect disk-full condition
- **Input**: Spool disk reaches 100%
- **Expected Behavior**: Metrics/health endpoint reports failure
- **Expected Output**: Alertable condition; logs written
- **Failure Condition**: Silent failure; no observability

---

## T21: Backpressure

### T21.1: Slow storage propagates backpressure
- **Description**: Delayed downstream slows ingestion
- **Input**: ClickHouse sink artificially slowed
- **Expected Behavior**: Ingestion rate decreases; memory bounded
- **Expected Output**: Queue depth grows to bound then stabilizes
- **Failure Condition**: Unbounded memory growth

### T21.2: Memory bounded under backpressure
- **Description**: Memory usage stays within limits
- **Input**: Sustained slow storage; high input rate
- **Expected Behavior**: Memory never exceeds configured limit
- **Expected Output**: Memory stays below threshold
- **Failure Condition**: OOM

---

## T22: High-Volume Benchmark

### T22.1: Tier 1 (10K events)
- **Description**: Basic throughput test
- **Input**: 10,000 synthetic events
- **Expected Behavior**: All events ingested, parsed, stored
- **Expected Output**: events/sec, MB/sec, latency percentiles reported
- **Failure Condition**: Event loss; timeout

### T22.2: Tier 2 (100K events)
- **Description**: Moderate throughput test
- **Input**: 100,000 synthetic events
- **Expected Behavior**: All events processed; metrics reported
- **Expected Output**: Throughput and resource metrics
- **Failure Condition**: Event loss; resource exhaustion

### T22.3: Tier 3 (1M events)
- **Description**: Heavy throughput test
- **Input**: 1,000,000 synthetic events
- **Expected Behavior**: All events processed
- **Expected Output**: Throughput and resource metrics
- **Failure Condition**: Event loss; resource exhaustion

### T22.4: Sustained throughput to saturation
- **Description**: Find maximum sustainable rate
- **Input**: Continuous event generation until CPU/disk saturated
- **Expected Behavior**: System stabilizes at max rate
- **Expected Output**: Saturation throughput reported
- **Failure Condition**: Crash; unbounded memory

---

## T23: Large Events

### T23.1: 1KB event
- **Description**: Small event boundary
- **Input**: 1024-byte event
- **Expected Behavior**: Ingested and preserved correctly
- **Expected Output**: Size matches; hash matches
- **Failure Condition**: Size mismatch

### T23.2: 4KB event
- **Description**: Typical large event
- **Input**: 4096-byte event
- **Expected Behavior**: Ingested correctly
- **Expected Output**: Size matches
- **Failure Condition**: Truncation

### T23.3: 16KB event
- **Description**: Large event
- **Input**: 16384-byte event
- **Expected Behavior**: Ingested correctly
- **Expected Output**: Size matches
- **Failure Condition**: Truncation

### T23.4: 64KB event
- **Description**: Very large event
- **Input**: 65536-byte event
- **Expected Behavior**: Ingested correctly
- **Expected Output**: Size matches
- **Failure Condition**: Truncation

### T23.5: 256KB event
- **Description**: Extremely large event
- **Input**: 262144-byte event
- **Expected Behavior**: Ingested correctly (or rejected per policy with raw preserved)
- **Expected Output**: Size matches or rejection with raw preserved
- **Failure Condition**: Silent truncation

### T23.6: 1MB+ event
- **Description**: Beyond typical limits
- **Input**: >1MB event
- **Expected Behavior**: Handled per max_event_size config
- **Expected Output**: Either ingested or cleanly rejected with raw preserved
- **Failure Condition**: Crash

---

## T24: Adversarial Inputs

### T24.1: Giant message
- **Description**: Message far exceeding limits
- **Input**: 100MB single "event"
- **Expected Behavior**: Rejected per policy; system stable; raw preserved in quarantine
- **Expected Output**: No crash; quarantine entry
- **Failure Condition**: OOM; crash

### T24.2: Deeply nested JSON
- **Description**: Pathological nesting depth
- **Input**: JSON nested 1000+ levels deep
- **Expected Behavior**: Parse depth limit enforced; raw preserved
- **Expected Output**: Controlled failure; no stack overflow
- **Failure Condition**: Stack overflow crash

### T24.3: Regex worst-case (ReDoS)
- **Description**: Pathological regex backtracking
- **Input**: Input designed to trigger catastrophic backtracking in regex
- **Expected Behavior**: Regex timeout enforced; raw preserved
- **Expected Output**: Parse timeout; no indefinite hang
- **Failure Condition**: Infinite loop; CPU starvation

### T24.4: Invalid encodings
- **Description**: Mixed/invalid character encodings
- **Input**: Bytes that are neither valid UTF-8 nor any single encoding
- **Expected Behavior**: Treated as binary; preserved verbatim
- **Expected Output**: Raw bytes intact
- **Failure Condition**: Encoding corruption

### T24.5: Repeated delimiters
- **Description**: Fields with repeated separator characters
- **Input**: `field1|||field2|||field3` with `|` delimiter
- **Expected Behavior**: Parse per documented behavior (empty fields, concat, etc.)
- **Expected Output**: Deterministic parse result
- **Failure Condition**: Crash; non-deterministic behavior

### T24.6: Parser ambiguity fields
- **Description**: Fields designed to confuse parsers
- **Input**: `"key=value key=\"quoted value with = sign\""`
- **Expected Behavior**: Parse per documented rules; deterministic
- **Expected Output**: Consistent field extraction
- **Failure Condition**: Crash; inconsistent results

---

## T25: Configuration Errors

### T25.1: Invalid parser config rejected at startup
- **Description**: Bad config fails fast
- **Input**: Parser config with missing required fields
- **Expected Behavior**: Validation fails at startup/activation time
- **Expected Output**: Clear error message; system refuses to start/activate
- **Failure Condition**: Invalid config accepted; data corruption later

### T25.2: Invalid OCSF mapping rejected
- **Description**: Mapping to non-existent OCSF field rejected
- **Input**: Mapping referencing non-existent OCSF attribute
- **Expected Behavior**: Schema validation catches invalid mapping
- **Expected Output**: Configuration rejected before processing
- **Failure Condition**: Invalid mapping accepted; runtime errors

### T25.3: Invalid regex in parser config
- **Description**: Bad regex pattern rejected at config time
- **Input**: Parser with invalid regex `(?P<name>unclosed(`
- **Expected Behavior**: Regex compilation fails at config validation
- **Expected Output**: Config rejected with clear error
- **Failure Condition**: Invalid regex accepted; runtime panic

---

## Test Execution Summary

| Phase | Test Families | Execution Order |
|-------|---------------|-----------------|
| 1 (no code) | T01-T25 definitions | Written before any production code |
| 2 (generators) | T07-T11 generators | Tests for generator output |
| 3 (ingestion) | T02, T05, T06 | Tests before ingestion code |
| 4 (spool) | T19, T20, T21 | Tests before spool code |
| 5 (parquet) | T01 (full verification) | Tests before Parquet code |
| 6 (parser) | T03, T04, T09-T11, T13, T24 | Tests before parser code |
| 7 (OCSF) | T18 | Tests before OCSF mapping code |
| 8 (ClickHouse) | T14-T17 | Tests before sink code |
| 10 (benchmark) | T22, T23, T12 | Tests before benchmark code |

---

## Coverage Matrix

| Requirement | Test Families |
|-------------|---------------|
| Lossless preservation | T01, T02, T17, T23, T24 |
| TCP ingestion | T02 |
| File ingestion | T05 |
| Syslog parsing | T03 |
| JSON parsing | T04 |
| Network device events | T07 |
| Linux server events | T08 |
| Application logs | T09 |
| Database logs | T10 |
| Windows logs | T11 |
| LogHub datasets | T12 |
| Parser configuration | T13 |
| Traceability | T14 |
| Duplicate handling | T15 |
| Out-of-order events | T16 |
| Parser failure | T17 |
| OCSF validation | T18 |
| Restart recovery | T19 |
| Disk-full behavior | T20 |
| Backpressure | T21 |
| Benchmark | T22 |
| Large events | T23 |
| Adversarial inputs | T24 |
| Configuration errors | T25 |
