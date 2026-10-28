"""Pydantic data models for SOC-Lite."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Event(BaseModel):
    event_uid: str
    timestamp: str
    host: str
    channel: str
    provider: Optional[str] = None
    event_id: int
    record_id: Optional[int] = None
    level: Optional[int] = 0
    category: str
    action: str
    user_name: Optional[str] = None
    user_domain: Optional[str] = None
    target_user: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    logon_type: Optional[int] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    summary: str
    raw: Dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    events: List[Event] = Field(..., max_length=1000)


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    alerts_created: int


class Alert(BaseModel):
    id: Optional[int] = None
    rule_id: str
    rule_name: str
    severity: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    host: str
    ts: str
    entity: Optional[str] = None
    description: str
    event_uids: List[str]
    dedupe_key: str
    status: str = "new"
    note: Optional[str] = None
    created_at: str
    updated_at: str


class AlertPatchRequest(BaseModel):
    status: Optional[str] = None
    note: Optional[str] = None


class TimeCount(BaseModel):
    t: str
    count: int


class NameCount(BaseModel):
    name: str
    count: int


class StatsOverview(BaseModel):
    total_events: int
    events_per_minute: List[TimeCount]
    top_event_ids: List[NameCount]
    failed_logons_by_ip: List[NameCount]
    alerts_by_severity: Dict[str, int]
    top_hosts: List[NameCount]
    ingest_rate_1m: float


class RuleModel(BaseModel):
    id: str
    name: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    enabled: bool = True
