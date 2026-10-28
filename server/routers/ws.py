"""WebSocket live stream endpoint coalescing events and pushing alerts."""

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from server.bus import bus
from server.config import settings
from server.db import Database

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/live")
async def websocket_live_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    sub_queue = bus.subscribe()
    db: Database = websocket.app.state.db

    # Send hello handshake
    hello_msg = {
        "type": "hello",
        "server_time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": "1.0.0",
    }
    await websocket.send_text(json.dumps(hello_msg))

    batch_interval_sec = max(0.1, settings.WS_BATCH_MS / 1000.0)
    coalesced_events: List[Dict[str, Any]] = []
    last_flush = time.time()
    last_stats_tick = time.time()

    try:
        while True:
            # Poll from queue with short timeout to allow batch flushing
            timeout = max(0.05, batch_interval_sec - (time.time() - last_flush))
            try:
                msg = await asyncio.wait_for(sub_queue.get(), timeout=timeout)
                msg_type = msg.get("type")
                if msg_type == "events":
                    coalesced_events.extend(msg.get("data", []))
                elif msg_type == "alert":
                    # Alerts pushed immediately without coalescing delay
                    await websocket.send_text(json.dumps(msg))
            except asyncio.TimeoutError:
                pass

            now = time.time()

            # Flush coalesced events if window elapsed and events exist
            if coalesced_events and (now - last_flush >= batch_interval_sec):
                # Send at most 200 events per message
                send_slice = coalesced_events[:200]
                coalesced_events = coalesced_events[200:]
                await websocket.send_text(json.dumps({"type": "events", "data": send_slice}))
                last_flush = now

            # Periodically broadcast quick stats (every 5 seconds)
            if now - last_stats_tick >= 5.0:
                try:
                    stats = await db.get_stats_overview(minutes=5)
                    open_alerts_res = await db.get_alerts(status="new", limit=100)
                    stats_payload = {
                        "type": "stats",
                        "data": {
                            "events_per_sec": stats.ingest_rate_1m,
                            "open_alerts": len(open_alerts_res),
                        },
                    }
                    await websocket.send_text(json.dumps(stats_payload))
                except Exception as e:
                    logger.debug(f"Error computing periodic stats for WS: {e}")
                last_stats_tick = now

    except (WebSocketDisconnect, ConnectionResetError):
        logger.debug("WebSocket client disconnected.")
    except Exception as e:
        logger.debug(f"WebSocket session error: {e}")
    finally:
        bus.unsubscribe(sub_queue)
