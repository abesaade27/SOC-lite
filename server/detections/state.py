"""State store and sliding-window event-time tracking for detection rules."""

from collections import deque
from datetime import datetime, timezone
import logging
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def parse_iso_ts(ts_str: str) -> float:
    try:
        if ts_str.endswith("Z"):
            ts_str = ts_str[:-1] + "+00:00"
        return datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        return datetime.now(timezone.utc).timestamp()


class SlidingWindow:
    def __init__(self, max_retention_seconds: int = 1800) -> None:
        self.max_retention = max_retention_seconds
        # Deque of (ts_float, key, uid, metadata_dict)
        self.events: Deque[Tuple[float, str, str, Dict[str, Any]]] = deque()

    def add(self, ts_float: float, key: str, uid: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        self.events.append((ts_float, key, uid, metadata or {}))
        self._evict_older_than(ts_float - self.max_retention)

    def _evict_older_than(self, cutoff_ts: float) -> None:
        while self.events and self.events[0][0] < cutoff_ts:
            self.events.popleft()

    def count_within(
        self, key: str, current_ts: float, window_seconds: float
    ) -> Tuple[int, List[str], List[Dict[str, Any]]]:
        cutoff = current_ts - window_seconds
        uids = []
        metas = []
        count = 0
        for ts, k, uid, meta in self.events:
            if k == key and cutoff <= ts <= current_ts + 60.0:  # 60s out-of-order tolerance
                count += 1
                uids.append(uid)
                metas.append(meta)
        return count, uids, metas


class StateStore:
    def __init__(self) -> None:
        self.windows: Dict[str, SlidingWindow] = {}
        # Cooldown tracker: dedupe_key -> last_alert_event_ts
        self.cooldowns: Dict[str, float] = {}
        # Key-value generic store for correlations (e.g. SOC-014 created accounts)
        # Store: store_name -> dict of key -> (ts_float, data)
        self.stores: Dict[str, Dict[str, Tuple[float, Any]]] = {}
        # System resume timestamp tracking for rate-based suppression
        self.last_resume_ts: float = 0.0

    def record_system_resume(self, ts_float: float) -> None:
        self.last_resume_ts = ts_float

    def is_resume_paused(self, current_ts: float, pause_seconds: float = 5.0) -> bool:
        if self.last_resume_ts > 0 and 0.0 <= (current_ts - self.last_resume_ts) < pause_seconds:
            return True
        return False

    def get_window(self, rule_id: str, max_retention: int = 1800) -> SlidingWindow:
        if rule_id not in self.windows:
            self.windows[rule_id] = SlidingWindow(max_retention_seconds=max_retention)
        return self.windows[rule_id]

    def is_in_cooldown(self, dedupe_key: str, event_ts: float, cooldown_seconds: int) -> bool:
        last_ts = self.cooldowns.get(dedupe_key)
        if last_ts is None:
            return False
        # If the new event timestamp is within cooldown_seconds of last_alert_ts
        if event_ts - last_ts < cooldown_seconds:
            return True
        return False

    def record_alert(self, dedupe_key: str, event_ts: float) -> None:
        self.cooldowns[dedupe_key] = event_ts

    def put_val(self, store_name: str, key: str, ts_float: float, val: Any) -> None:
        if store_name not in self.stores:
            self.stores[store_name] = {}
        self.stores[store_name][key] = (ts_float, val)

    def get_val(
        self, store_name: str, key: str, current_ts: float, max_age_seconds: float
    ) -> Optional[Any]:
        store = self.stores.get(store_name)
        if not store:
            return None
        item = store.get(key)
        if not item:
            return None
        ts_float, val = item
        if current_ts - ts_float <= max_age_seconds:
            return val
        # Expired
        store.pop(key, None)
        return None

    def clear(self) -> None:
        self.windows.clear()
        self.cooldowns.clear()
        self.stores.clear()
