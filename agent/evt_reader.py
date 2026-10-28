"""Windows Event Log reader supporting EvtSubscribe, backfill, and polling fallback."""

import ctypes
import logging
import queue
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set
import xml.etree.ElementTree as ET

from .normalizer import normalize_event_xml

logger = logging.getLogger(__name__)

# Windows API availability check
HAS_WIN32 = False
if sys.platform == "win32":
    try:
        import win32evtlog
        HAS_WIN32 = True
    except ImportError:
        logger.warning("pywin32 (win32evtlog) is not installed; live Windows event collection unavailable.")


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class WindowsEventReader:
    def __init__(
        self,
        config: Dict[str, Any],
        output_queue: queue.Queue,
        get_bookmark_fn: Any,
    ) -> None:
        self.config = config
        self.output_queue = output_queue
        self.get_bookmark_fn = get_bookmark_fn
        self.channels: List[Dict[str, str]] = config.get("channels", [])
        self.security_allowlist: Set[int] = set(config.get("security_event_allowlist", []))
        self.host_override = config.get("host_override")
        self.mode = config.get("mode", "subscribe")
        self.poll_interval = config.get("poll_interval_seconds", 2)
        self.backfill_on_start = config.get("backfill_on_start", True)
        self.backfill_max = config.get("backfill_max_events", 5000)

        self.running = False
        self.subscriptions: List[Any] = []
        self.poll_thread: Optional[threading.Thread] = None

    def verify_prerequisites(self) -> bool:
        if not HAS_WIN32:
            logger.error("win32evtlog is required on Windows for live event collection.")
            return False

        has_security = any(c.get("name") == "Security" for c in self.channels)
        if has_security and not is_admin():
            logger.error(
                "Access Denied: Administrative privileges are required to read the Windows Security event log. "
                "Please run the agent from an elevated command prompt (Run as Administrator)."
            )
            return False
        return True

    def _render_event(self, event_handle: Any) -> Optional[str]:
        try:
            return win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
        except Exception as e:
            logger.debug(f"EvtRender error: {e}")
            return None

    def _process_xml(self, xml_str: str) -> None:
        normalized = normalize_event_xml(xml_str, host_override=self.host_override)
        if not normalized:
            return

        # Security allowlist filtering
        if normalized["channel"] == "Security" and self.security_allowlist:
            if normalized["event_id"] not in self.security_allowlist:
                return

        self.output_queue.put(normalized)

    def _subscription_callback(self, action: int, context: Any, event_handle: Any) -> int:
        if action == win32evtlog.EvtSubscribeActionDeliver:
            xml_data = self._render_event(event_handle)
            if xml_data:
                self._process_xml(xml_data)
        elif action == win32evtlog.EvtSubscribeActionError:
            logger.warning(f"EvtSubscribe error reported for context: {context}")
        return 0

    def _backfill_channel(self, channel_name: str, xpath: str) -> None:
        if not HAS_WIN32:
            return
        last_id = self.get_bookmark_fn(channel_name)
        logger.info(f"Checking backfill for {channel_name} (bookmark={last_id})")

        try:
            if last_id > 0:
                query_xpath = f"*[System[EventRecordID > {last_id}]]"
                flags = win32evtlog.EvtQueryChannelPath
                query = win32evtlog.EvtQuery(channel_name, flags, query_xpath)
                while self.running:
                    events = win32evtlog.EvtNext(query, 100)
                    if not events:
                        break
                    for ev in events:
                        xml_str = self._render_event(ev)
                        if xml_str:
                            self._process_xml(xml_str)
            else:
                # First run with no bookmark: read latest backfill_max in reverse, then process
                flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection
                query = win32evtlog.EvtQuery(channel_name, flags, xpath or "*")
                events = win32evtlog.EvtNext(query, min(self.backfill_max, 500))
                if events:
                    for ev in reversed(events):
                        xml_str = self._render_event(ev)
                        if xml_str:
                            self._process_xml(xml_str)
        except Exception as e:
            logger.warning(f"Could not backfill channel {channel_name}: {e}")

    def start(self) -> None:
        if not HAS_WIN32:
            logger.warning("Agent reader starting in no-op mode (non-Windows platform).")
            return

        self.running = True

        for ch in self.channels:
            name = ch.get("name")
            xpath = ch.get("xpath") or "*"
            if not name:
                continue

            if self.backfill_on_start:
                self._backfill_channel(name, xpath)

            if self.mode == "subscribe":
                try:
                    sub = win32evtlog.EvtSubscribe(
                        name,
                        win32evtlog.EvtSubscribeToFutureEvents,
                        Query=xpath,
                        Callback=self._subscription_callback,
                        Context=name,
                    )
                    self.subscriptions.append(sub)
                    logger.info(f"Subscribed to channel: {name}")
                except Exception as e:
                    logger.warning(f"Failed to subscribe to channel {name} (may not exist on this OS): {e}")

        if self.mode == "poll":
            self.poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self.poll_thread.start()
            logger.info("Started polling loop for event channels.")

    def _poll_loop(self) -> None:
        while self.running:
            for ch in self.channels:
                name = ch.get("name")
                xpath = ch.get("xpath") or "*"
                if not name:
                    continue
                last_id = self.get_bookmark_fn(name)
                query_xpath = f"*[System[EventRecordID > {last_id}]]"
                try:
                    query = win32evtlog.EvtQuery(name, win32evtlog.EvtQueryChannelPath, query_xpath)
                    while self.running:
                        events = win32evtlog.EvtNext(query, 100)
                        if not events:
                            break
                        for ev in events:
                            xml_str = self._render_event(ev)
                            if xml_str:
                                self._process_xml(xml_str)
                except Exception as e:
                    logger.debug(f"Poll query failed for {name}: {e}")
            time.sleep(self.poll_interval)

    def stop(self) -> None:
        self.running = False
        self.subscriptions.clear()
