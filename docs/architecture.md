# SOC-Lite Architecture & Design Decisions

SOC-Lite is a lightweight, self-contained Security Operations Center pipeline engineered for Windows environments. It collects, normalizes, detects, and visualizes security telemetry without high operational overhead.

```
┌──────────────────────┐   HTTPS/HTTP POST (batched JSON, X-API-Key)   ┌────────────────────────────┐
│  Windows Agent       │ ───────────────────────────────────────────▶ │  Ingestor API (FastAPI)    │
│  - EvtSubscribe      │                                               │  - validate (pydantic)     │
│  - normalize         │ ◀──── 200 {accepted, duplicates} ───────────  │  - dedupe + store (SQLite) │
│  - bookmark          │                                               │  - run detection engine    │
│  - spool on failure  │                                               │  - broadcast over WS       │
└──────────────────────┘                                               └─────────────┬──────────────┘
                                                                                     │ WebSocket /ws/live
                                                                                     │ REST /api/*
                                                                       ┌─────────────▼──────────────┐
                                                                       │ Dashboard (localhost:8000) │
                                                                       │ live feed, charts, alerts  │
                                                                       └────────────────────────────┘
```

## Key Architectural Decisions

### 1. Push Subscriptions (`EvtSubscribe`) vs. Periodic Polling
Polling event logs introduces artificial latency and requires repetitive heavy queries. Using `win32evtlog.EvtSubscribe` allows Windows kernel event providers to push events into user space immediately upon generation. The agent callback extracts the XML and enqueues it to a thread-safe memory queue, decoupling Windows callback execution from network I/O.

### 2. SQLite in WAL Mode as Primary Datastore
For single-host and small-cluster defensive monitoring, SQLite in Write-Ahead Logging (`WAL`) mode provides:
- High ingestion throughput with atomic writes.
- Concurrent reads without blocking the write lock (`PRAGMA synchronous = NORMAL`).
- Zero external database daemon dependencies.
- Simple portability and automated hourly retention purging.

### 3. Event-Time Windows vs. Wall-Clock Windows
Detection engines that rely on wall-clock time fail when network spikes or machine sleep delays event shipping. SOC-Lite parses the event's own `SystemTime` (`timestamp`) and correlates detections within event-time sliding windows. It tolerates out-of-order event arrival up to 60 seconds.

### 4. Cooldown and Deduplication
To prevent alert fatigue when an adversary runs automated scripts (e.g. dozens of failed passwords), each detection rule generates a unique `dedupe_key` (e.g. `SOC-001:192.168.1.100`). Alerts are suppressed during a configurable cooldown period (e.g. 300 seconds), appending new evidence to the initial alert window rather than spamming analysts.

### 5. Resilient Spooling and Bookmarks
Network interruptions between the agent and ingest server are handled via local disk spooling (`./spool/<timestamp>.jsonl`). Spool size is bounded by a strict quota (`spool_max_mb`). When connectivity resumes, spooled events are replayed oldest-first, and record bookmarks are updated atomically (`bookmarks.json`).

### 6. WebSocket Event Coalescing
High-volume event bursts can freeze browser render threads. The server's WebSocket broadcaster buffers incoming events and flushes them in batches every `WS_BATCH_MS` (500ms default), ensuring a smooth 60fps operator experience on the dashboard.
