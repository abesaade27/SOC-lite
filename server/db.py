"""Database layer utilizing SQLite in WAL mode with aiosqlite."""

import asyncio
from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
import aiosqlite

from .models import Alert, Event, NameCount, StatsOverview, TimeCount

logger = logging.getLogger(__name__)

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  event_uid     TEXT NOT NULL UNIQUE,
  ts            TEXT NOT NULL,
  received_at   TEXT NOT NULL,
  host          TEXT NOT NULL,
  channel       TEXT NOT NULL,
  provider      TEXT,
  event_id      INTEGER NOT NULL,
  record_id     INTEGER,
  level         INTEGER,
  category      TEXT NOT NULL,
  action        TEXT NOT NULL,
  user_name     TEXT,
  user_domain   TEXT,
  target_user   TEXT,
  src_ip        TEXT,
  src_port      INTEGER,
  dst_ip        TEXT,
  dst_port      INTEGER,
  logon_type    INTEGER,
  process_name  TEXT,
  process_id    INTEGER,
  parent_process TEXT,
  command_line  TEXT,
  summary       TEXT NOT NULL,
  raw_json      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_eid_ts    ON events(event_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_host_ts   ON events(host, ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events(category, ts);
"""

CREATE_ALERTS_TABLE = """
CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id         TEXT NOT NULL,
  rule_name       TEXT NOT NULL,
  severity        TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  mitre_tactic    TEXT,
  mitre_technique TEXT,
  host            TEXT NOT NULL,
  ts              TEXT NOT NULL,
  entity          TEXT,
  description     TEXT NOT NULL,
  event_uids      TEXT NOT NULL,
  dedupe_key      TEXT NOT NULL,
  status          TEXT NOT NULL DEFAULT 'new',
  note            TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_status_ts ON alerts(status, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_dedupe    ON alerts(dedupe_key, ts);
"""


class Database:
    def __init__(self, db_path: str = "soc_lite.db") -> None:
        self.db_path = db_path
        self._write_lock = asyncio.Lock()

    async def init_db(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)) or ".", exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute("PRAGMA foreign_keys=ON;")
            await db.executescript(CREATE_EVENTS_TABLE)
            await db.executescript(CREATE_ALERTS_TABLE)
            await db.commit()
        logger.info(f"Database initialized in WAL mode at {self.db_path}")

    async def insert_events(self, events: List[Event]) -> Tuple[List[Event], int]:
        if not events:
            return [], 0

        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        new_events: List[Event] = []
        duplicates = 0

        async with self._write_lock:
            async with aiosqlite.connect(self.db_path) as db:
                for ev in events:
                    try:
                        cursor = await db.execute(
                            """
                            INSERT OR IGNORE INTO events (
                                event_uid, ts, received_at, host, channel, provider,
                                event_id, record_id, level, category, action,
                                user_name, user_domain, target_user,
                                src_ip, src_port, dst_ip, dst_port,
                                logon_type, process_name, process_id, parent_process,
                                command_line, summary, raw_json
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                ev.event_uid,
                                ev.timestamp,
                                now_iso,
                                ev.host,
                                ev.channel,
                                ev.provider,
                                ev.event_id,
                                ev.record_id,
                                ev.level,
                                ev.category,
                                ev.action,
                                ev.user_name,
                                ev.user_domain,
                                ev.target_user,
                                ev.src_ip,
                                ev.src_port,
                                ev.dst_ip,
                                ev.dst_port,
                                ev.logon_type,
                                ev.process_name,
                                ev.process_id,
                                ev.parent_process,
                                ev.command_line,
                                ev.summary,
                                json.dumps(ev.raw),
                            ),
                        )
                        if cursor.rowcount > 0:
                            new_events.append(ev)
                        else:
                            duplicates += 1
                    except Exception as e:
                        logger.error(f"Error inserting event {ev.event_uid}: {e}")
                await db.commit()

        return new_events, duplicates

    async def insert_alert(self, alert: Alert) -> int:
        async with self._write_lock:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute(
                    """
                    INSERT INTO alerts (
                        rule_id, rule_name, severity, mitre_tactic, mitre_technique,
                        host, ts, entity, description, event_uids, dedupe_key,
                        status, note, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert.rule_id,
                        alert.rule_name,
                        alert.severity,
                        alert.mitre_tactic,
                        alert.mitre_technique,
                        alert.host,
                        alert.ts,
                        alert.entity,
                        alert.description,
                        json.dumps(alert.event_uids),
                        alert.dedupe_key,
                        alert.status,
                        alert.note,
                        alert.created_at,
                        alert.updated_at,
                    ),
                )
                await db.commit()
                return cursor.lastrowid or 0

    async def get_events(
        self,
        limit: int = 100,
        before_id: Optional[int] = None,
        host: Optional[str] = None,
        channel: Optional[str] = None,
        event_id: Optional[int] = None,
        category: Optional[str] = None,
        query_str: Optional[str] = None,
        since_iso: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params: List[Any] = []

        if before_id:
            conditions.append("id < ?")
            params.append(before_id)
        if host:
            conditions.append("host = ?")
            params.append(host)
        if channel:
            conditions.append("channel = ?")
            params.append(channel)
        if event_id:
            conditions.append("event_id = ?")
            params.append(event_id)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if since_iso:
            conditions.append("ts >= ?")
            params.append(since_iso)
        if query_str:
            like_val = f"%{query_str}%"
            conditions.append(
                "(summary LIKE ? OR command_line LIKE ? OR user_name LIKE ? OR src_ip LIKE ?)"
            )
            params.extend([like_val, like_val, like_val, like_val])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM events {where_clause} ORDER BY id DESC LIMIT ?"
        params.append(min(limit, 500))

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
            results = []
            for r in rows:
                row_dict = dict(r)
                row_dict["raw"] = json.loads(row_dict.pop("raw_json", "{}"))
                row_dict["timestamp"] = row_dict.pop("ts")
                results.append(row_dict)
            return results

    async def get_event_by_id(self, event_id_val: int) -> Optional[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM events WHERE id = ?", (event_id_val,))
            row = await cursor.fetchone()
            if not row:
                return None
            row_dict = dict(row)
            row_dict["raw"] = json.loads(row_dict.pop("raw_json", "{}"))
            row_dict["timestamp"] = row_dict.pop("ts")
            return row_dict

    async def get_events_by_uids(self, uids: List[str]) -> List[Dict[str, Any]]:
        if not uids:
            return []
        placeholders = ",".join("?" for _ in uids)
        sql = f"SELECT * FROM events WHERE event_uid IN ({placeholders}) ORDER BY id DESC"
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, uids)
            rows = await cursor.fetchall()
            results = []
            for r in rows:
                row_dict = dict(r)
                row_dict["raw"] = json.loads(row_dict.pop("raw_json", "{}"))
                row_dict["timestamp"] = row_dict.pop("ts")
                results.append(row_dict)
            return results

    async def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        before_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params: List[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if before_id:
            conditions.append("id < ?")
            params.append(before_id)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM alerts {where_clause} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, params)
            rows = await cursor.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                d["event_uids"] = json.loads(d.get("event_uids", "[]"))
                results.append(d)
            return results

    async def update_alert(
        self, alert_id: int, status: Optional[str] = None, note: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        updates = ["updated_at = ?"]
        params: List[Any] = [now_iso]

        if status:
            updates.append("status = ?")
            params.append(status)
        if note is not None:
            updates.append("note = ?")
            params.append(note)

        params.append(alert_id)
        sql = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?"

        async with self._write_lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute(sql, params)
                await db.commit()

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
            row = await cursor.fetchone()
            if row:
                d = dict(row)
                d["event_uids"] = json.loads(d.get("event_uids", "[]"))
                return d
            return None

    async def get_stats_overview(self, minutes: int = 60) -> StatsOverview:
        async with aiosqlite.connect(self.db_path) as db:
            # Total events
            cursor = await db.execute("SELECT COUNT(*) FROM events")
            total_events = (await cursor.fetchone())[0]

            # Ingest rate last 1m
            cursor = await db.execute(
                "SELECT COUNT(*) FROM events WHERE received_at >= datetime('now', '-1 minute')"
            )
            count_1m = (await cursor.fetchone())[0]
            ingest_rate_1m = round(count_1m / 60.0, 2)

            # Events per minute
            cursor = await db.execute(
                f"""
                SELECT strftime('%Y-%m-%dT%H:%M:00Z', ts) as minute_bucket, COUNT(*) as count
                FROM events
                WHERE ts >= datetime('now', '-{minutes} minutes')
                GROUP BY minute_bucket
                ORDER BY minute_bucket ASC
                """
            )
            rows = await cursor.fetchall()
            events_per_minute = [TimeCount(t=r[0], count=r[1]) for r in rows if r[0]]

            # Top event IDs
            cursor = await db.execute(
                f"""
                SELECT event_id, COUNT(*) as count
                FROM events
                WHERE ts >= datetime('now', '-{minutes} minutes')
                GROUP BY event_id
                ORDER BY count DESC
                LIMIT 10
                """
            )
            rows = await cursor.fetchall()
            top_event_ids = [NameCount(name=str(r[0]), count=r[1]) for r in rows]

            # Failed logons by IP
            cursor = await db.execute(
                f"""
                SELECT src_ip, COUNT(*) as count
                FROM events
                WHERE event_id = 4625 AND src_ip IS NOT NULL AND ts >= datetime('now', '-{minutes} minutes')
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT 10
                """
            )
            rows = await cursor.fetchall()
            failed_logons_by_ip = [NameCount(name=r[0], count=r[1]) for r in rows]

            # Alerts by severity
            cursor = await db.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            )
            rows = await cursor.fetchall()
            alerts_by_sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
            for sev, cnt in rows:
                if sev in alerts_by_sev:
                    alerts_by_sev[sev] = cnt

            # Top hosts
            cursor = await db.execute(
                f"""
                SELECT host, COUNT(*) as count
                FROM events
                WHERE ts >= datetime('now', '-{minutes} minutes')
                GROUP BY host
                ORDER BY count DESC
                LIMIT 10
                """
            )
            rows = await cursor.fetchall()
            top_hosts = [NameCount(name=r[0], count=r[1]) for r in rows]

            return StatsOverview(
                total_events=total_events,
                events_per_minute=events_per_minute,
                top_event_ids=top_event_ids,
                failed_logons_by_ip=failed_logons_by_ip,
                alerts_by_severity=alerts_by_sev,
                top_hosts=top_hosts,
                ingest_rate_1m=ingest_rate_1m,
            )

    async def get_health(self) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM events")
            count = (await cursor.fetchone())[0]

        size_mb = 0.0
        if os.path.exists(self.db_path):
            size_mb = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)

        return {"status": "ok", "events": count, "db_size_mb": size_mb}

    async def get_recent_events_for_warmup(self, minutes: int = 10) -> List[Event]:
        sql = f"""
        SELECT * FROM events
        WHERE ts >= datetime('now', '-{minutes} minutes')
        ORDER BY ts ASC
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql)
            rows = await cursor.fetchall()
            events = []
            for r in rows:
                d = dict(r)
                raw = json.loads(d.pop("raw_json", "{}"))
                events.append(
                    Event(
                        event_uid=d["event_uid"],
                        timestamp=d["ts"],
                        host=d["host"],
                        channel=d["channel"],
                        provider=d["provider"],
                        event_id=d["event_id"],
                        record_id=d["record_id"],
                        level=d["level"],
                        category=d["category"],
                        action=d["action"],
                        user_name=d["user_name"],
                        user_domain=d["user_domain"],
                        target_user=d["target_user"],
                        src_ip=d["src_ip"],
                        src_port=d["src_port"],
                        dst_ip=d["dst_ip"],
                        dst_port=d["dst_port"],
                        logon_type=d["logon_type"],
                        process_name=d["process_name"],
                        process_id=d["process_id"],
                        parent_process=d["parent_process"],
                        command_line=d["command_line"],
                        summary=d["summary"],
                        raw=raw,
                    )
                )
            return events
