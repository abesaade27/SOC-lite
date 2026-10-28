"""Shipper thread for batching, shipping events, retry, spooling, and bookmarking."""

import json
import logging
import os
import queue
import time
from typing import Any, Callable, Dict, List, Optional
import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

logger = logging.getLogger(__name__)


class EventShipper:
    def __init__(
        self,
        server_url: str,
        api_key: str,
        event_queue: queue.Queue,
        batch_size: int = 100,
        flush_interval_seconds: float = 2.0,
        spool_dir: str = "./spool",
        spool_max_mb: int = 200,
        tls_verify: bool = True,
        on_success_callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.event_queue = event_queue
        self.batch_size = batch_size
        self.flush_interval = flush_interval_seconds
        self.spool_dir = os.path.abspath(spool_dir)
        self.spool_max_mb = spool_max_mb
        self.tls_verify = tls_verify
        self.on_success = on_success_callback
        self.running = False

        os.makedirs(self.spool_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": self.api_key, "Content-Type": "application/json"})

    def _post_batch(self, events: List[Dict[str, Any]]) -> bool:
        @retry(
            reraise=True,
            stop=stop_after_attempt(4),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            retry=retry_if_exception_type(requests.RequestException),
        )
        def _do_post() -> requests.Response:
            url = f"{self.server_url}/api/ingest"
            resp = self.session.post(url, json={"events": events}, timeout=10, verify=self.tls_verify)
            resp.raise_for_status()
            return resp

        try:
            _do_post()
            return True
        except Exception as e:
            logger.warning(f"Failed to ship batch of {len(events)} events: {e}")
            return False

    def _spool_batch(self, events: List[Dict[str, Any]]) -> None:
        self._enforce_spool_quota()
        filename = f"{int(time.time() * 1000)}.jsonl"
        filepath = os.path.join(self.spool_dir, filename)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev) + "\n")
            logger.info(f"Spooled {len(events)} events to {filename}")
        except Exception as e:
            logger.error(f"Failed to spool batch to {filepath}: {e}")

    def _enforce_spool_quota(self) -> None:
        try:
            files = [
                os.path.join(self.spool_dir, f)
                for f in os.listdir(self.spool_dir)
                if f.endswith(".jsonl")
            ]
            files.sort(key=lambda x: os.path.getmtime(x))
            total_size_mb = sum(os.path.getsize(f) for f in files) / (1024 * 1024)

            while total_size_mb > self.spool_max_mb and files:
                oldest = files.pop(0)
                sz_mb = os.path.getsize(oldest) / (1024 * 1024)
                os.remove(oldest)
                total_size_mb -= sz_mb
                logger.warning(f"Spool quota exceeded: deleted oldest spool file {oldest}")
        except Exception as e:
            logger.warning(f"Spool quota maintenance error: {e}")

    def replay_spool(self) -> None:
        try:
            files = [
                os.path.join(self.spool_dir, f)
                for f in os.listdir(self.spool_dir)
                if f.endswith(".jsonl")
            ]
            files.sort(key=lambda x: os.path.getmtime(x))
            for fpath in files:
                events = []
                with open(fpath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            events.append(json.loads(line))
                if events:
                    if self._post_batch(events):
                        os.remove(fpath)
                        logger.info(f"Successfully replayed and removed spool {os.path.basename(fpath)}")
                        if self.on_success:
                            self.on_success(events)
                    else:
                        break  # Stop replay on failure
        except Exception as e:
            logger.error(f"Error during spool replay: {e}")

    def run_loop(self) -> None:
        self.running = True
        batch: List[Dict[str, Any]] = []
        last_flush = time.time()

        while self.running:
            try:
                timeout = max(0.1, self.flush_interval - (time.time() - last_flush))
                try:
                    ev = self.event_queue.get(timeout=timeout)
                    batch.append(ev)
                except queue.Empty:
                    pass

                now = time.time()
                should_flush = len(batch) >= self.batch_size or (batch and (now - last_flush >= self.flush_interval))

                if should_flush:
                    success = self._post_batch(batch)
                    if success:
                        if self.on_success:
                            self.on_success(batch)
                        # Attempt to replay spool files on successful connection
                        self.replay_spool()
                    else:
                        self._spool_batch(batch)
                        if self.on_success:
                            # Spooled batches are persisted on disk; update bookmarks
                            self.on_success(batch)
                    batch = []
                    last_flush = now
            except Exception as e:
                logger.error(f"Shipper loop error: {e}")

        # Flush remaining
        if batch:
            if self._post_batch(batch):
                if self.on_success:
                    self.on_success(batch)
            else:
                self._spool_batch(batch)
                if self.on_success:
                    self.on_success(batch)

    def stop(self) -> None:
        self.running = False
