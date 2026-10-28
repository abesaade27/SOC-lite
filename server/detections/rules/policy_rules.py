"""Policy and log tampering detection rules: SOC-005."""

from typing import List
from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..state import StateStore, parse_iso_ts


class SOC005AuditLogCleared(Rule):
    id = "SOC-005"
    name = "Audit log cleared"
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "T1070.001"
    description = "A Windows Event Log (Security or System) was intentionally cleared."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Security 1102 or System 104
        if not (
            (ev.channel == "Security" and ev.event_id == 1102)
            or (ev.channel == "System" and ev.event_id == 104)
        ):
            return []

        user = ev.user_name or "SYSTEM"
        ts_float = parse_iso_ts(ev.timestamp)
        dedupe_key = f"{self.id}:{ev.host}:{ev.channel}"

        if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            desc = f"Windows {ev.channel} audit log was cleared on host {ev.host} by user '{user}'."
            return [
                AlertPayload(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    host=ev.host,
                    ts=ev.timestamp,
                    entity=user,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []
