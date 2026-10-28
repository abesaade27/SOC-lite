"""Data retention background cleaner."""

import asyncio
import logging
import aiosqlite
from .config import settings

logger = logging.getLogger(__name__)


async def run_retention_loop(db_path: str, check_interval_hours: int = 1) -> None:
    logger.info(f"Retention task active: deleting events > {settings.RETENTION_DAYS} days, alerts > 90 days.")
    while True:
        try:
            async with aiosqlite.connect(db_path) as db:
                c1 = await db.execute(
                    f"DELETE FROM events WHERE ts < datetime('now', '-{settings.RETENTION_DAYS} days')"
                )
                c2 = await db.execute(
                    "DELETE FROM alerts WHERE ts < datetime('now', '-90 days')"
                )
                await db.commit()
                if c1.rowcount or c2.rowcount:
                    logger.info(
                        f"Retention cleanup purged {c1.rowcount} old events and {c2.rowcount} old alerts."
                    )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Retention background cleaner error: {e}")

        await asyncio.sleep(check_interval_hours * 3600)
