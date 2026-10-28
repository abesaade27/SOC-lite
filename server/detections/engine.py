"""Detection engine that orchestrates rule evaluation, state, and warm-up."""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional
import yaml

from server.models import Alert, Event
from .base import AlertPayload, Rule
from .rules import ALL_RULES
from .state import StateStore

logger = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, config_path: Optional[str] = None) -> None:
        self.state = StateStore()
        self.rules: List[Rule] = list(ALL_RULES)
        self.rule_errors: Dict[str, int] = {r.id: 0 for r in self.rules}
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), "rules.yaml")
        self.load_rule_config()

    def load_rule_config(self) -> None:
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f) or {}
                for rule in self.rules:
                    if rule.id in cfg:
                        rc = cfg[rule.id]
                        if "enabled" in rc:
                            rule.enabled = bool(rc["enabled"])
                        if "cooldown_seconds" in rc:
                            rule.cooldown_seconds = int(rc["cooldown_seconds"])
                        if "threshold" in rc and hasattr(rule, "threshold"):
                            setattr(rule, "threshold", int(rc["threshold"]))
                        if "window_seconds" in rc and hasattr(rule, "window_seconds"):
                            setattr(rule, "window_seconds", int(rc["window_seconds"]))
                logger.info(f"Loaded rules configuration from {self.config_path}")
            except Exception as e:
                logger.warning(f"Failed to parse {self.config_path}: {e}")

    def evaluate(self, event: Event, silent: bool = False) -> List[Alert]:
        alerts: List[Alert] = []
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        for rule in self.rules:
            if not rule.enabled:
                continue

            try:
                payloads: List[AlertPayload] = rule.evaluate(event, self.state)
                if not silent and payloads:
                    for p in payloads:
                        alerts.append(
                            Alert(
                                rule_id=p.rule_id,
                                rule_name=p.rule_name,
                                severity=p.severity.value,
                                mitre_tactic=p.mitre_tactic,
                                mitre_technique=p.mitre_technique,
                                host=p.host,
                                ts=p.ts,
                                entity=p.entity,
                                description=p.description,
                                event_uids=p.event_uids,
                                dedupe_key=p.dedupe_key,
                                status="new",
                                note=None,
                                created_at=now_iso,
                                updated_at=now_iso,
                            )
                        )
            except Exception as e:
                self.rule_errors[rule.id] = self.rule_errors.get(rule.id, 0) + 1
                logger.error(f"Rule {rule.id} failed while evaluating event {event.event_uid}: {e}")

        return alerts

    def warmup(self, events: List[Event]) -> None:
        logger.info(f"Warming up detection engine with {len(events)} historical events...")
        sorted_events = sorted(events, key=lambda x: x.timestamp)
        for ev in sorted_events:
            self.evaluate(ev, silent=True)
        logger.info("Detection engine warmup complete.")


engine = DetectionEngine()
