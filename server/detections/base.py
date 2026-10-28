"""Base definitions and abstract class for detection rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional
from server.models import Event


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AlertPayload:
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    host: str
    ts: str
    entity: Optional[str]
    description: str
    event_uids: List[str]
    dedupe_key: str


class Rule(ABC):
    id: str
    name: str
    severity: Severity
    mitre_tactic: str
    mitre_technique: str
    description: str
    enabled: bool = True
    cooldown_seconds: int = 300

    @abstractmethod
    def evaluate(self, ev: Event, state: Any) -> List[AlertPayload]:
        pass
