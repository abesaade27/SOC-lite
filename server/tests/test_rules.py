"""Detection rules unit and scenario replay tests."""

import json
import os
import pytest

from server.detections.engine import DetectionEngine
from server.models import Event


def make_test_event(
    event_id: int,
    ts: str = "2026-10-27T18:00:00Z",
    host: str = "LAB-WIN10",
    channel: str = "Security",
    category: str = "auth",
    action: str = "test",
    user_name: str = "alice",
    src_ip: str = None,
    command_line: str = None,
    raw: dict = None,
    uid: str = "test_uid",
) -> Event:
    return Event(
        event_uid=uid,
        timestamp=ts,
        host=host,
        channel=channel,
        event_id=event_id,
        category=category,
        action=action,
        user_name=user_name,
        src_ip=src_ip,
        command_line=command_line,
        summary=f"Event {event_id}",
        raw=raw or {},
    )


def test_soc001_sliding_window_and_cooldown():
    engine = DetectionEngine()

    # 4 failures within 10s: should NOT alert yet (threshold = 5)
    alerts = []
    for i in range(4):
        ev = make_test_event(
            event_id=4625,
            ts=f"2026-10-27T18:00:0{i}Z",
            src_ip="192.168.1.50",
            uid=f"f_{i}",
        )
        alerts.extend(engine.evaluate(ev))
    assert len(alerts) == 0

    # 5th failure: triggers SOC-001!
    ev5 = make_test_event(
        event_id=4625,
        ts="2026-10-27T18:00:05Z",
        src_ip="192.168.1.50",
        uid="f_4",
    )
    alerts5 = engine.evaluate(ev5)
    assert len(alerts5) == 1
    assert alerts5[0].rule_id == "SOC-001"

    # 6th failure right after: within cooldown (300s), so NO duplicate alert
    ev6 = make_test_event(
        event_id=4625,
        ts="2026-10-27T18:00:06Z",
        src_ip="192.168.1.50",
        uid="f_5",
    )
    alerts6 = engine.evaluate(ev6)
    assert len(alerts6) == 0


def test_soc001_window_expiry():
    engine = DetectionEngine()
    # 5 events spaced 70s apart: never more than 1 in 60s window
    alerts = []
    for i in range(5):
        minute = i * 2
        ev = make_test_event(
            event_id=4625,
            ts=f"2026-10-27T18:{minute:02d}:00Z",
            src_ip="10.0.0.99",
            uid=f"slow_{i}",
        )
        alerts.extend(engine.evaluate(ev))
    assert len(alerts) == 0


def test_soc005_audit_log_cleared():
    engine = DetectionEngine()
    ev = make_test_event(
        event_id=1102,
        channel="Security",
        category="policy",
        action="audit_log_cleared",
        uid="clear_1",
    )
    alerts = engine.evaluate(ev)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SOC-005"
    assert alerts[0].severity == "critical"


def test_soc007_encoded_powershell():
    engine = DetectionEngine()
    ev = make_test_event(
        event_id=4688,
        channel="Security",
        category="process",
        action="process_create",
        command_line="powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAiAA==",
        uid="ps_1",
    )
    alerts = engine.evaluate(ev)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SOC-007"
    assert "Decoded:" in alerts[0].description


def test_replay_attack_scenario():
    engine = DetectionEngine()
    scenario_file = os.path.join(
        os.path.dirname(__file__), "..", "..", "sample_data", "attack_scenario.jsonl"
    )
    assert os.path.exists(scenario_file), "attack_scenario.jsonl must exist"

    fired_rule_ids = set()
    with open(scenario_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                ev_data = json.loads(line)
                ev = Event(**ev_data)
                alerts = engine.evaluate(ev)
                for a in alerts:
                    fired_rule_ids.add(a.rule_id)

    # Verify that the scripted scenario triggers all expected rules!
    expected_rules = {
        "SOC-001",  # Brute force
        "SOC-002",  # Logon after failures
        "SOC-003",  # User created
        "SOC-004",  # Admin group added
        "SOC-014",  # Rapid new-account + admin add chain
        "SOC-007",  # Encoded powershell
        "SOC-006",  # New service in Public
        "SOC-009",  # Scheduled task
        "SOC-010",  # LSASS access
        "SOC-005",  # Audit log cleared
    }
    missing = expected_rules - fired_rule_ids
    assert not missing, f"Attack scenario failed to fire rules: {missing}"
