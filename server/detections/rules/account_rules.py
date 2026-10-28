"""Account management detection rules: SOC-003, SOC-004, SOC-011, and SOC-014."""

import re
from typing import List
from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..state import StateStore, parse_iso_ts

ADMIN_GROUP_SID = "S-1-5-32-544"
ADMIN_GROUP_REGEX = re.compile(r"^(Administrators|Domain Admins|Enterprise Admins)$", re.IGNORECASE)


class SOC003LocalUserCreated(Rule):
    id = "SOC-003"
    name = "Local user account created"
    severity = Severity.MEDIUM
    mitre_tactic = "Persistence"
    mitre_technique = "T1136.001"
    description = "A new local user account was created."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id != 4720:
            return []

        creator = ev.user_name or "SYSTEM"
        target = ev.target_user or "unknown"
        ts_float = parse_iso_ts(ev.timestamp)

        # Store in state for correlation rule SOC-014
        state.put_val("account_created", target.lower(), ts_float, (ev.event_uid, creator, ev.host))

        # Check upgrade condition: hidden account ($) or unusual creator
        severity = self.severity
        notes = []
        if target.endswith("$"):
            severity = Severity.HIGH
            notes.append("account name ends with $ (possible hidden/service account)")

        known_admins = {"administrator", "admin", "system"}
        if creator.lower() not in known_admins and not creator.endswith("$"):
            severity = Severity.HIGH
            notes.append(f"created by non-standard account '{creator}'")

        note_str = f" ({'; '.join(notes)})" if notes else ""
        desc = f"New user account '{target}' was created by '{creator}'{note_str}."
        dedupe_key = f"{self.id}:{ev.host}:{target.lower()}"

        if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            return [
                AlertPayload(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=severity,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    host=ev.host,
                    ts=ev.timestamp,
                    entity=target,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC004PrivilegedGroupMemberAdded(Rule):
    id = "SOC-004"
    name = "User added to privileged group"
    severity = Severity.HIGH
    mitre_tactic = "Privilege Escalation"
    mitre_technique = "T1098"
    description = "A user account was added to a high-privilege administrative group."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id not in (4728, 4732, 4756):
            return []

        group_sid = ev.raw.get("TargetSid") or ""
        group_name = ev.raw.get("TargetUserName") or ""

        is_privileged = (
            group_sid.upper() == ADMIN_GROUP_SID
            or bool(ADMIN_GROUP_REGEX.search(group_name))
        )
        if not is_privileged:
            return []

        target_member = ev.target_user or ev.raw.get("MemberName") or ev.raw.get("MemberSid") or "unknown"
        actor = ev.user_name or "SYSTEM"
        ts_float = parse_iso_ts(ev.timestamp)

        desc = f"User '{target_member}' was added to privileged group '{group_name or group_sid}' by '{actor}'."
        dedupe_key = f"{self.id}:{ev.host}:{target_member.lower()}"

        if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            return [
                AlertPayload(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    host=ev.host,
                    ts=ev.timestamp,
                    entity=target_member,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC011AccountLockout(Rule):
    id = "SOC-011"
    name = "Account lockout"
    severity = Severity.MEDIUM
    mitre_tactic = "Credential Access"
    mitre_technique = "T1110"
    description = "User account was locked out following repeated authentication failures."
    cooldown_seconds = 300

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id != 4740:
            return []

        target = ev.target_user or "unknown"
        caller = ev.raw.get("TargetDomainName") or ev.host
        ts_float = parse_iso_ts(ev.timestamp)
        dedupe_key = f"{self.id}:{target.lower()}"

        if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            desc = f"Account '{target}' was locked out on {ev.host} (caller computer: {caller})."
            return [
                AlertPayload(
                    rule_id=self.id,
                    rule_name=self.name,
                    severity=self.severity,
                    mitre_tactic=self.mitre_tactic,
                    mitre_technique=self.mitre_technique,
                    host=ev.host,
                    ts=ev.timestamp,
                    entity=target,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC014RapidNewAccountAdminChain(Rule):
    id = "SOC-014"
    name = "Rapid new-account + admin add chain"
    severity = Severity.CRITICAL
    mitre_tactic = "Persistence"
    mitre_technique = "T1136.001"
    description = "A newly created user account was rapidly elevated to the Administrators group within 10 minutes."
    cooldown_seconds = 300
    window_seconds = 600

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id not in (4728, 4732, 4756):
            return []

        group_sid = ev.raw.get("TargetSid") or ""
        group_name = ev.raw.get("TargetUserName") or ""

        is_privileged = (
            group_sid.upper() == ADMIN_GROUP_SID
            or bool(ADMIN_GROUP_REGEX.search(group_name))
        )
        if not is_privileged:
            return []

        target_member = ev.target_user or ev.raw.get("MemberName") or ev.raw.get("MemberSid") or ""
        # Strip domain if present (e.g. DOMAIN\svc_backup$ -> svc_backup$)
        clean_target = target_member.split("\\")[-1].strip().lower()
        if not clean_target:
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        account_create_data = state.get_val("account_created", clean_target, ts_float, self.window_seconds)

        if account_create_data:
            create_uid, creator, original_host = account_create_data
            dedupe_key = f"{self.id}:{clean_target}"
            if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
                state.record_alert(dedupe_key, ts_float)
                desc = (
                    f"Rapid account creation and administrative elevation chain detected: "
                    f"Account '{clean_target}' created by '{creator}' and added to "
                    f"'{group_name or 'Administrators'}' within 10 minutes."
                )
                return [
                    AlertPayload(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        mitre_tactic=self.mitre_tactic,
                        mitre_technique=self.mitre_technique,
                        host=ev.host,
                        ts=ev.timestamp,
                        entity=clean_target,
                        description=desc,
                        event_uids=[create_uid, ev.event_uid],
                        dedupe_key=dedupe_key,
                    )
                ]
        return []
