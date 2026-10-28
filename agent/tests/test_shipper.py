"""Tests for EventShipper batching and spooling."""

import os
import queue
import shutil
import tempfile
from agent.shipper import EventShipper


def test_shipper_spools_on_failure() -> None:
    temp_dir = tempfile.mkdtemp()
    try:
        q: queue.Queue = queue.Queue()
        ev = {
            "event_uid": "test12345",
            "timestamp": "2026-10-27T18:00:00Z",
            "host": "TEST-HOST",
            "channel": "Security",
            "event_id": 4624,
            "category": "auth",
            "action": "logon_success",
            "summary": "Test event",
        }
        q.put(ev)

        shipper = EventShipper(
            server_url="http://127.0.0.1:59999",  # Unreachable port
            api_key="TEST_KEY",
            event_queue=q,
            batch_size=1,
            flush_interval_seconds=0.1,
            spool_dir=temp_dir,
        )

        # Trigger flush
        success = shipper._post_batch([ev])
        assert not success

        # Directly test spooling
        shipper._spool_batch([ev])
        spool_files = os.listdir(temp_dir)
        assert len(spool_files) == 1
        assert spool_files[0].endswith(".jsonl")

        with open(os.path.join(temp_dir, spool_files[0]), "r", encoding="utf-8") as f:
            content = f.read()
            assert "test12345" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
