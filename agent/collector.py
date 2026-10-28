"""SOC-Lite Windows Log Collector CLI entrypoint."""

import argparse
import datetime
import json
import logging
import os
import queue
import random
import sys
import threading
import time
from typing import Any, Dict, List
import requests
import yaml

from .bookmarks import BookmarkManager
from .evt_reader import WindowsEventReader, is_admin, HAS_WIN32
from .shipper import EventShipper

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("soc-collector")


def load_config(config_path: str) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        example_path = os.path.join(os.path.dirname(config_path), "config.example.yaml")
        if os.path.exists(example_path):
            logger.info(f"Config {config_path} not found. Loading defaults from {example_path}")
            config_path = example_path
        else:
            raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_check(config: Dict[str, Any]) -> int:
    logger.info("Running system and connectivity checks...")
    success = True

    # 1. Platform & Admin Check
    if sys.platform == "win32":
        logger.info(f"Platform: Windows. pywin32 available: {HAS_WIN32}")
        admin = is_admin()
        logger.info(f"Administrative privileges: {'YES' if admin else 'NO'}")
        if not admin:
            logger.warning("Agent requires elevated privileges to read Windows Security Event Log.")
            success = False
    else:
        logger.info(f"Platform: {sys.platform} (Non-Windows - live event capture requires Windows)")

    # 2. Server connectivity & API key check
    server_url = config.get("server_url", "http://127.0.0.1:8000").rstrip("/")
    api_key = config.get("api_key", "")
    try:
        health_resp = requests.get(f"{server_url}/healthz", timeout=5)
        if health_resp.status_code == 200:
            logger.info(f"Server reachable at {server_url} (Health: OK)")
        else:
            logger.warning(f"Server health check failed: {health_resp.status_code}")
            success = False
    except Exception as e:
        logger.error(f"Cannot connect to server at {server_url}: {e}")
        return 1

    try:
        ingest_test = requests.post(
            f"{server_url}/api/ingest",
            headers={"X-API-Key": api_key},
            json={"events": []},
            timeout=5,
        )
        if ingest_test.status_code == 200:
            logger.info("API Key authenticated successfully.")
        elif ingest_test.status_code == 401:
            logger.error("API Key rejected by server (401 Unauthorized).")
            success = False
        else:
            logger.info(f"Ingest endpoint responded with {ingest_test.status_code}")
    except Exception as e:
        logger.error(f"Failed to test ingest endpoint: {e}")
        success = False

    return 0 if success else 2


def run_replay(file_path: str, rate: float, server_url: str, api_key: str) -> None:
    if not os.path.exists(file_path):
        logger.error(f"Replay file not found: {file_path}")
        sys.exit(1)

    logger.info(f"Replaying events from {file_path} at {rate} events/s...")
    events: List[Dict[str, Any]] = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

    logger.info(f"Loaded {len(events)} events for replay.")
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    delay = 1.0 / max(rate, 0.1)

    batch: List[Dict[str, Any]] = []
    for ev in events:
        batch.append(ev)
        if len(batch) >= 10:
            try:
                requests.post(f"{server_url}/api/ingest", headers=headers, json={"events": batch}, timeout=10)
            except Exception as e:
                logger.warning(f"Replay POST error: {e}")
            batch = []
            time.sleep(delay * 10)
        else:
            time.sleep(delay)

    if batch:
        try:
            requests.post(f"{server_url}/api/ingest", headers=headers, json={"events": batch}, timeout=10)
        except Exception as e:
            logger.warning(f"Replay final POST error: {e}")

    logger.info("Replay completed.")


def run_simulate(rate: float, server_url: str, api_key: str) -> None:
    logger.info(f"Running synthetic event simulator at {rate} events/sec. Press Ctrl+C to stop.")
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    delay = 1.0 / max(rate, 0.1)
    record_counter = 500000

    users = ["alice", "bob", "carol", "svc_backup", "admin"]
    hosts = ["DESKTOP-SOC1", "SERVER-DC01", "WORKSTATION-X"]
    ips = ["192.168.1.15", "192.168.1.22", "10.0.0.45", "10.0.0.88"]

    try:
        while True:
            record_counter += 1
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            user = random.choice(users)
            host = random.choice(hosts)
            ip = random.choice(ips)

            # 90% benign, 10% suspicious
            is_suspicious = random.random() < 0.10
            if is_suspicious:
                eid = random.choice([4625, 4104, 7045])
                if eid == 4625:
                    cat, action = "auth", "logon_failure"
                    summary = f"Simulated logon failure for {user} from {ip}"
                elif eid == 4104:
                    cat, action = "powershell", "script_block"
                    summary = "Simulated powershell script block execution"
                else:
                    cat, action = "service", "service_install"
                    summary = "Simulated service installation"
            else:
                eid = random.choice([4624, 4634, 4688])
                if eid == 4624:
                    cat, action = "auth", "logon_success"
                    summary = f"Simulated logon for {user}"
                elif eid == 4634:
                    cat, action = "auth", "logoff"
                    summary = f"Simulated logoff for {user}"
                else:
                    cat, action = "process", "process_create"
                    summary = f"Simulated process creation by {user}"

            ev = {
                "event_uid": f"sim_{host}_{eid}_{record_counter}",
                "timestamp": now_iso,
                "host": host,
                "channel": "Security",
                "provider": "SOC-Simulator",
                "event_id": eid,
                "record_id": record_counter,
                "level": 0,
                "category": cat,
                "action": action,
                "user_name": user,
                "user_domain": "CORP",
                "target_user": None,
                "src_ip": ip,
                "src_port": random.randint(1024, 65535),
                "dst_ip": None,
                "dst_port": None,
                "logon_type": 3 if eid in (4624, 4625) else None,
                "process_name": "cmd.exe" if eid == 4688 else None,
                "process_id": random.randint(1000, 9999),
                "parent_process": "explorer.exe",
                "command_line": f"cmd.exe /c echo {user}" if eid == 4688 else None,
                "summary": summary,
                "raw": {"Simulated": "True"},
            }

            try:
                requests.post(f"{server_url}/api/ingest", headers=headers, json={"events": [ev]}, timeout=5)
            except Exception as e:
                logger.debug(f"Simulator ship error: {e}")

            time.sleep(delay)
    except KeyboardInterrupt:
        logger.info("Simulator stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC-Lite Windows Event Log Collector")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--check", action="store_true", help="Verify environment, channels, and server connection")
    parser.add_argument("--print-only", action="store_true", help="Print normalized events to stdout without shipping")
    parser.add_argument("--replay", type=str, help="Replay a JSONL event file at specified rate")
    parser.add_argument("--simulate", action="store_true", help="Run synthetic event generation")
    parser.add_argument("--rate", type=float, default=5.0, help="Rate in events/sec for replay or simulation")
    args = parser.parse_args()

    cfg = load_config(args.config)

    if args.check:
        sys.exit(run_check(cfg))

    server_url = cfg.get("server_url", "http://127.0.0.1:8000")
    api_key = cfg.get("api_key", "CHANGE_ME")

    if args.replay:
        run_replay(args.replay, args.rate, server_url, api_key)
        return

    if args.simulate:
        run_simulate(args.rate, server_url, api_key)
        return

    event_queue: queue.Queue = queue.Queue(maxsize=10000)
    bookmarks = BookmarkManager(cfg.get("bookmark_file", "./bookmarks.json"))

    def on_batch_success(batch: List[Dict[str, Any]]) -> None:
        for ev in batch:
            ch = ev.get("channel")
            rid = ev.get("record_id")
            if ch and rid:
                bookmarks.update_record_id(ch, rid)
        bookmarks.save()

    if args.print_only:
        logger.info("Running in --print-only mode. Normalized events will print to stdout.")

        def print_worker() -> None:
            while True:
                ev = event_queue.get()
                print(json.dumps(ev))
                event_queue.task_done()

        t = threading.Thread(target=print_worker, daemon=True)
        t.start()
        reader = WindowsEventReader(cfg, event_queue, bookmarks.get_last_record_id)
        if not reader.verify_prerequisites():
            sys.exit(2)
        reader.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            reader.stop()
            logger.info("Stopped.")
        return

    shipper = EventShipper(
        server_url=server_url,
        api_key=api_key,
        event_queue=event_queue,
        batch_size=cfg.get("batch_size", 100),
        flush_interval_seconds=cfg.get("flush_interval_seconds", 2),
        spool_dir=cfg.get("spool_dir", "./spool"),
        spool_max_mb=cfg.get("spool_max_mb", 200),
        tls_verify=cfg.get("tls_verify", True),
        on_success_callback=on_batch_success,
    )

    reader = WindowsEventReader(cfg, event_queue, bookmarks.get_last_record_id)
    if not reader.verify_prerequisites():
        logger.warning("Prerequisites check failed or non-Windows system; proceeding to start shipper.")

    shipper_thread = threading.Thread(target=shipper.run_loop, daemon=True)
    shipper_thread.start()
    reader.start()

    logger.info("SOC-Lite Agent running. Press Ctrl+C to terminate.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down agent...")
        reader.stop()
        shipper.stop()
        shipper_thread.join(timeout=3)
        bookmarks.save()
        logger.info("Agent stopped cleanly.")


if __name__ == "__main__":
    main()
