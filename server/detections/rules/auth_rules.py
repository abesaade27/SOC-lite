"""Authentication detection rules: SOC-001 and SOC-002."""

import logging
from typing import List
from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..net_utils import get_network_group_key, is_non_private_ip
from ..state import StateStore, parse_iso_ts

logger = logging.getLogger(__name__)


class SOC001BruteForceLogon(Rule):
    id = "SOC-001"
    name = "Brute-force logon failures"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110.001"
    description = "Multiple failed logon attempts detected within a short time window."
    cooldown_seconds = 300
    threshold = 5
    window_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id != 4625:
            return []

        # False-positive tuning: ignore machine accounts ending in "$"
        target = ev.target_user or ev.user_name or ""
        if target.endswith("$"):
            return []

        ts_float = parse_iso_ts(ev.timestamp)

        # Laptop lifecycle: pause rate-based evaluation for 5 seconds after sleep resume
        if state.is_resume_paused(ts_float):
            return []

        # Group network alerts by subnet/gateway MAC/FQDN instead of raw DHCP IP
        if ev.src_ip and ev.src_ip not in ("127.0.0.1", "localhost", "::1"):
            net_group = get_network_group_key(ev.src_ip, ev.raw)
            group_key = f"{ev.host}:{net_group}"
            entity = f"{ev.src_ip} ({net_group})"
        else:
            user = target or "unknown"
            group_key = f"local:{user}@{ev.host}"
            entity = f"{user} (local)"

        window = state.get_window(self.id, max_retention=300)
        user_targeted = target or "unknown"
        window.add(ts_float, group_key, ev.event_uid, {"user": user_targeted, "logon_type": ev.logon_type})

        # Also store failed logons for SOC-002 tracking
        fail_tracker = state.get_window("TRACK_4625_FAILURES", max_retention=600)
        fail_tracker.add(ts_float, group_key, ev.event_uid, {"user": user_targeted, "ip": ev.src_ip, "logon_type": ev.logon_type})
        if user_targeted:
            fail_tracker.add(ts_float, user_targeted.lower(), ev.event_uid, {"ip": ev.src_ip, "logon_type": ev.logon_type})

        count, uids, metas = window.count_within(group_key, ts_float, self.window_seconds)

        dedupe_key = f"{self.id}:{group_key}"
        if count >= self.threshold and not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            targets = sorted(list({m.get("user", "") for m in metas if m.get("user")}))
            targets_str = ", ".join(targets[:5]) or "unknown"

            # False-positive severity tuning:
            # LogonType 2 and 7 (interactive / unlock) -> low severity
            # LogonType 3 and 10 from non-private source IP -> high severity
            if ev.logon_type in (2, 7):
                alert_sev = Severity.LOW
            elif ev.logon_type in (3, 10):
                alert_sev = Severity.HIGH if is_non_private_ip(ev.src_ip) else Severity.MEDIUM
            else:
                alert_sev = self.severity

            desc = (
                f"{entity} produced {count} failed logons in {self.window_seconds}s (logon type: {ev.logon_type or '?'}) "
                f"targeting users: {targets_str}"
            )
            return [
                AlertPayload(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=alert_sev,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    host=ev.host,
                    ts=ev.timestamp,
                    entity=entity,
                    description=desc,
                    event_uids=uids,
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC002LogonAfterFailures(Rule):
    id = "SOC-002"
    name = "Successful logon after repeated failures"
    severity = Severity.CRITICAL
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110"
    description = "Successful authentication following a high volume of failed logon attempts."
    cooldown_seconds = 300
    prior_failures_threshold = 5
    window_seconds = 300

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id != 4624:
            return []

        # False-positive tuning: ignore machine accounts ending in "$"
        target = ev.target_user or ev.user_name or ""
        if target.endswith("$"):
            return []

        user = target.lower()
        ip = ev.src_ip or ""
        ts_float = parse_iso_ts(ev.timestamp)

        fail_tracker = state.get_window("TRACK_4625_FAILURES", max_retention=600)
        # Check by IP, network group, or by username
        net_group = get_network_group_key(ip, ev.raw) if ip else ""
        count_ip, uids_ip, _ = fail_tracker.count_within(ip, ts_float, self.window_seconds) if ip else (0, [], [])
        count_net, uids_net, _ = fail_tracker.count_within(f"{ev.host}:{net_group}", ts_float, self.window_seconds) if net_group else (0, [], [])
        count_user, uids_user, _ = (
            fail_tracker.count_within(user, ts_float, self.window_seconds) if user else (0, [], [])
        )

        total_failures = max(count_ip, count_net, count_user)
        if total_failures >= self.prior_failures_threshold:
            entity = f"{ev.user_name or user}@{ip or 'local'}"
            dedupe_key = f"{self.id}:{entity}"
            if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
                state.record_alert(dedupe_key, ts_float)
                all_uids = list(set(uids_ip + uids_net + uids_user + [ev.event_uid]))

                # False-positive tuning for severity:
                # LogonType 2 and 7 -> low severity
                # LogonType 3 and 10 from non-private source IP -> critical
                if ev.logon_type in (2, 7):
                    alert_sev = Severity.LOW
                elif ev.logon_type in (3, 10):
                    alert_sev = Severity.CRITICAL if is_non_private_ip(ip) else Severity.HIGH
                else:
                    alert_sev = self.severity

                desc = (
                    f"Successful logon for {ev.user_name} from {ip or 'local'} (type {ev.logon_type}) "
                    f"after {total_failures} recent logon failures."
                )
                return [
                    AlertPayload(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=alert_sev,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        host=ev.host,
                        ts=ev.timestamp,
                        entity=entity,
                        description=desc,
                        event_uids=all_uids,
                        dedupe_key=dedupe_key,
                    )
                ]
        return []
