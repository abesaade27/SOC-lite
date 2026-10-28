"""Bookmark persistence for tracking ingested Windows Event record IDs."""

import json
import logging
import os
import tempfile
from typing import Dict

logger = logging.getLogger(__name__)


class BookmarkManager:
    def __init__(self, filepath: str = "./bookmarks.json") -> None:
        self.filepath = os.path.abspath(filepath)
        self.bookmarks: Dict[str, int] = {}
        self.load()

    def load(self) -> Dict[str, int]:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.bookmarks = {k: int(v) for k, v in data.items()}
            except Exception as e:
                logger.warning(f"Failed to read bookmark file {self.filepath}: {e}")
                self.bookmarks = {}
        else:
            self.bookmarks = {}
        return self.bookmarks

    def get_last_record_id(self, channel: str) -> int:
        return self.bookmarks.get(channel, 0)

    def update_record_id(self, channel: str, record_id: int) -> None:
        current = self.bookmarks.get(channel, 0)
        if record_id > current:
            self.bookmarks[channel] = record_id

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.filepath) or ".", exist_ok=True)
        dir_name = os.path.dirname(self.filepath) or "."
        try:
            with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                json.dump(self.bookmarks, tf, indent=2)
                temp_name = tf.name
            os.replace(temp_name, self.filepath)
        except Exception as e:
            logger.error(f"Failed to write bookmark file {self.filepath}: {e}")
