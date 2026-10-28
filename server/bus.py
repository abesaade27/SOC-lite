"""In-process asynchronous event bus for WebSocket subscribers."""

import asyncio
import logging
from typing import Any, Dict, Set

logger = logging.getLogger(__name__)


class EventBus:
    def __init__(self, max_queue_size: int = 1000) -> None:
        self.subscribers: Set[asyncio.Queue] = set()
        self.max_queue_size = max_queue_size

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self.max_queue_size)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def publish(self, kind: str, payload: Any) -> None:
        msg: Dict[str, Any] = {"type": kind, "data": payload}
        for q in list(self.subscribers):
            try:
                if q.full():
                    try:
                        q.get_nowait()  # Drop oldest event if subscriber queue is full
                    except asyncio.QueueEmpty:
                        pass
                q.put_nowait(msg)
            except Exception as e:
                logger.debug(f"Failed to deliver bus message to subscriber: {e}")


bus = EventBus()
