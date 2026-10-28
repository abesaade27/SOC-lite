"""Integration tests for Server REST API endpoints."""

import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from server.config import settings
from server.db import Database
from server.main import app


@pytest.fixture
def client():
    # Use temporary sqlite database for tests
    temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    temp_db.close()
    old_db = settings.DB_PATH
    settings.DB_PATH = temp_db.name

    test_db = Database(temp_db.name)
    app.state.db = test_db

    with TestClient(app) as test_client:
        yield test_client

    settings.DB_PATH = old_db
    try:
        os.remove(temp_db.name)
    except Exception:
        pass


def test_healthz(client: TestClient):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "events" in data


def test_ingest_auth_failure(client: TestClient):
    resp = client.post("/api/ingest", json={"events": []})
    assert resp.status_code == 401


def test_ingest_and_deduplication(client: TestClient):
    headers = {"X-API-Key": settings.API_KEY}
    events = [
        {
            "event_uid": "api_test_uid_1",
            "timestamp": "2026-10-27T18:00:00Z",
            "host": "TEST-HOST",
            "channel": "Security",
            "event_id": 4624,
            "category": "auth",
            "action": "logon_success",
            "user_name": "alice",
            "summary": "Successful logon",
            "raw": {},
        }
    ]

    # First ingest: accepted=1, duplicates=0
    resp1 = client.post("/api/ingest", headers=headers, json={"events": events})
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["accepted"] == 1
    assert data1["duplicates"] == 0

    # Second ingest of same event: accepted=0, duplicates=1
    resp2 = client.post("/api/ingest", headers=headers, json={"events": events})
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["accepted"] == 0
    assert data2["duplicates"] == 1

    # Query events
    events_resp = client.get("/api/events?limit=10")
    assert events_resp.status_code == 200
    evs = events_resp.json()
    assert len(evs) == 1
    assert evs[0]["event_uid"] == "api_test_uid_1"


def test_alert_patch_lifecycle(client: TestClient):
    headers = {"X-API-Key": settings.API_KEY}
    # Trigger an alert by sending 5 failed logons (SOC-001)
    failed_events = [
        {
            "event_uid": f"fail_uid_{i}",
            "timestamp": f"2026-10-27T18:01:0{i}Z",
            "host": "TEST-HOST",
            "channel": "Security",
            "event_id": 4625,
            "category": "auth",
            "action": "logon_failure",
            "user_name": "bob",
            "src_ip": "10.10.10.10",
            "summary": "Failed logon",
            "raw": {"IpAddress": "10.10.10.10"},
        }
        for i in range(5)
    ]
    ingest_resp = client.post("/api/ingest", headers=headers, json={"events": failed_events})
    assert ingest_resp.status_code == 200
    assert ingest_resp.json()["alerts_created"] >= 1

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]
    assert alerts[0]["status"] == "new"

    # Patch status to acknowledged
    patch_resp = client.patch(
        f"/api/alerts/{alert_id}", json={"status": "ack", "note": "Investigating"}
    )
    assert patch_resp.status_code == 200
    patched = patch_resp.json()
    assert patched["status"] == "ack"
    assert patched["note"] == "Investigating"
