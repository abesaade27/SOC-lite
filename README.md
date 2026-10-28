# SOC-Lite: Windows Log Collector, Detection Engine and Live Dashboard

> Lightweight, real-time Security Operations Center pipeline for Windows endpoint monitoring, behavioral threat detection, and telemetry visualization.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20(Replay)-lightgrey.svg)](#)

---

## Architecture

```
┌──────────────────────┐   HTTP/HTTPS POST (batched JSON, X-API-Key)   ┌────────────────────────────┐
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

## Features

- **Windows Event Log Ingest**: Kernel push subscriptions (`EvtSubscribe`) with automatic startup backfill and disk spooling on network outage.
- **Canonical Schema Normalizer**: Standardizes Windows Security, System, PowerShell, Sysmon, and Defender events into a uniform, typed format.
- **In-Memory & Stateful Detection Engine**: 14 built-in detection rules mapped to MITRE ATT&CK tactics with event-time sliding windows, multi-event correlation, and alert cooldown suppression.
- **Zero-Build Live Dashboard**: High-performance dark SOC console built with plain HTML, vanilla JS, Chart.js, and native WebSockets. Features live event filtering, search, alert triage workflows, and JSON inspection drawers.
- **Platform Agnostic Evaluation**: Includes synthetic simulator and deterministic replay modes (`--replay`) allowing full demonstration and testing on any OS without requiring live Windows logs.

---

## Quick Start

### 1. Replay Mode (Instant Demo - No Windows or Admin Required)

Ideal for trying SOC-Lite on macOS, Linux, or non-admin Windows machines:

```bash
# Clone and setup virtual environment
git clone https://github.com/example/soc-lite.git
cd soc-lite
python -m venv .venv
# On Windows: .venv\Scripts\activate
# On Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt

# Start the ingest server
cp .env.example .env
uvicorn server.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:
```bash
# Replay scripted multi-stage attack scenario
python -m agent.collector --replay sample_data/attack_scenario.jsonl --rate 10
```

Open `http://127.0.0.1:8000` in your browser to observe the live incident feed, velocity charts, and triggered alerts.

---

### 2. Live Windows Monitoring (Run as Administrator)

For live event collection from your Windows machine or VM:

```powershell
# In an elevated PowerShell prompt (Run as Administrator)
cd soc-lite
copy .env.example .env
copy agent\config.example.yaml agent\config.yaml

# Start the server
uvicorn server.main:app --host 127.0.0.1 --port 8000

# In another elevated terminal, start the agent collector
python -m agent.collector --config agent\config.yaml
```

To verify environment prerequisites, run:
```powershell
python -m agent.collector --config agent\config.yaml --check
```

---

### 3. Docker Deployment (Server)

```bash
docker compose up -d
```
The dashboard and ingest API will be reachable at `http://127.0.0.1:8000`.

---

## Detection Rules Catalog

| ID | Rule Name | Severity | MITRE Tactic / Technique | Channel / Event ID |
|---|---|---|---|---|
| **SOC-001** | Brute-force logon failures | High | Credential Access / T1110.001 | Security 4625 |
| **SOC-002** | Successful logon after repeated failures | Critical | Credential Access / T1110 | Security 4624 |
| **SOC-003** | Local user account created | Medium | Persistence / T1136.001 | Security 4720 |
| **SOC-004** | User added to privileged group | High | Privilege Escalation / T1098 | Security 4728 / 4732 / 4756 |
| **SOC-005** | Audit log cleared | Critical | Defense Evasion / T1070.001 | Security 1102, System 104 |
| **SOC-006** | New service installed | Medium / High | Persistence / T1543.003 | System 7045, Security 4697 |
| **SOC-007** | Encoded / obfuscated PowerShell | High | Execution / T1059.001 | Security 4688, Sysmon 1 |
| **SOC-008** | LOLBin abuse for download / proxy execution | High | Defense Evasion / T1218 | Security 4688, Sysmon 1 |
| **SOC-009** | Scheduled task created | Medium / High | Persistence / T1053.005 | Security 4698, schtasks.exe |
| **SOC-010** | LSASS memory access | Critical | Credential Access / T1003.001 | Sysmon 10 |
| **SOC-011** | Account lockout | Medium | Credential Access / T1110 | Security 4740 |
| **SOC-012** | Defender protection disabled | High | Defense Evasion / T1562.001 | Defender 5001/5010/5012, 4688 |
| **SOC-013** | Suspicious parent-child process | High | Execution / T1204.002 | Security 4688, Sysmon 1 |
| **SOC-014** | Rapid new-account + admin add chain | Critical | Persistence / T1136.001 + T1098 | Security 4720 + 4732 |

---

## Testing & Quality

Run the automated test suite with `pytest`:
```bash
pytest -v
```

Code formatting and style checks:
```bash
ruff check .
```

---

## Project Structure

```
soc-lite/
├── agent/
│   ├── collector.py           # CLI entrypoint (run, replay, simulate, check)
│   ├── evt_reader.py          # EvtSubscribe / backfill / polling reader
│   ├── normalizer.py          # XML to canonical event schema
│   ├── shipper.py             # Batching HTTP shipper with disk spool
│   ├── bookmarks.py           # Atomic JSON bookmark tracker
│   └── tests/
├── server/
│   ├── main.py                # FastAPI factory, lifespan, CSP headers
│   ├── config.py              # Pydantic settings
│   ├── models.py              # Pydantic models for events, alerts, stats
│   ├── db.py                  # aiosqlite WAL database manager
│   ├── auth.py                # X-API-Key authentication
│   ├── bus.py                 # Asyncio in-process pub/sub event bus
│   ├── retention.py           # Automated background data cleaner
│   ├── routers/               # Ingest, Events, Alerts, Stats, WebSocket
│   ├── detections/            # Engine, StateStore, YAML rules, 14 detectors
│   └── tests/
├── dashboard/
│   ├── index.html             # Responsive single-page SOC dashboard
│   ├── styles.css             # Cyberpunk/Dark SOC theme CSS
│   ├── app.js                 # Vanilla JS state, Chart.js, WS handler
│   └── vendor/                # Pinned Chart.js fallback
├── sample_data/               # Deterministic attack and benign datasets
├── tools/                     # Sample generators, sanitizer, attack sim
└── docs/                      # Architecture, rules, Windows configuration
```

---

## Roadmap

- [ ] Sigma rule converter (`pySigma`) integration.
- [ ] Optional OpenSearch backend profile for multi-gigabyte log retention.
- [ ] MaxMind GeoLite2 offline GeoIP enrichment.
- [ ] Multi-tenant agent authorization with per-host keys.

---

## Responsible Use & Limitations

- **Lab & Educational Focus**: SOC-Lite is engineered for learning detection engineering, blue teaming, and lab monitoring.
- **Single Host Default**: Binds to `127.0.0.1` by default. For distributed setups, secure with TLS and a reverse proxy (e.g. Caddy).
- **Safe Testing**: Attack simulations in `tools/attack_sim.ps1` execute safe commands for detection validation. Always run tests in dedicated lab VMs.

---

## License

This project is licensed under the [MIT License](LICENSE).
