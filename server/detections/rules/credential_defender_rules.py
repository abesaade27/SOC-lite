"""LSASS credential dumping and Defender disabling rules: SOC-010 and SOC-012."""

import re
from typing import List
from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..state import StateStore, parse_iso_ts

LSASS_SUSPICIOUS_ACCESS = {"0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff"}
LSASS_ALLOWLIST = {"msmpeng.exe", "csrss.exe", "wininit.exe", "svchost.exe"}

DEFENDER_DISABLE_CMD_REGEX = re.compile(
    r"(Set-MpPreference.*-(DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring)\s+\$true|sc(?:\.exe)?\s+stop\s+WinDefend)",
    re.IGNORECASE,
)


class SOC010LSASSMemoryAccess(Rule):
    id = "SOC-010"
    name = "LSASS memory access"
    severity = Severity.CRITICAL
    mitre_tactic = "Credential Access"
    mitre_technique = "T1003.001"
    description = "Suspicious process access to lsass.exe memory space indicates possible credential dumping."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 10
        if not (ev.channel == "Microsoft-Windows-Sysmon/Operational" and ev.event_id == 10):
            return []

        target_img = (ev.raw.get("TargetImage") or "").lower()
        if not target_img.endswith("\\lsass.exe"):
            return []

        access_mask = (ev.raw.get("GrantedAccess") or "").strip().lower()
        if access_mask not in LSASS_SUSPICIOUS_ACCESS:
            return []

        source_img = (ev.process_name or ev.raw.get("SourceImage") or "").lower()
        source_base = source_img.split("\\")[-1]

        if source_base in LSASS_ALLOWLIST:
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        call_trace = ev.raw.get("CallTrace", "")[:100]
        desc = (
            f"Suspicious memory access to lsass.exe by binary '{source_img}' "
            f"(GrantedAccess: {access_mask}). CallTrace preview: {call_trace}"
        )
        dedupe_key = f"{self.id}:{ev.host}:{source_base}"

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
                    entity=source_base,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC012DefenderDisabled(Rule):
    id = "SOC-012"
    name = "Defender protection disabled"
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion"
    mitre_technique = "T1562.001"
    description = "Windows Defender Antivirus real-time or behavior protection was disabled."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        is_defender_event = ev.event_id in (5001, 5010, 5012) and "Defender" in ev.channel
        is_disable_cmd = False

        if ev.event_id in (4688, 1) and ev.command_line:
            if DEFENDER_DISABLE_CMD_REGEX.search(ev.command_line):
                is_disable_cmd = True

        if not (is_defender_event or is_disable_cmd):
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        detail = (
            f"via command: {ev.command_line}"
            if is_disable_cmd
            else f"via Defender Event ID {ev.event_id}"
        )
        desc = f"Windows Defender protection was disabled on {ev.host} {detail} by '{ev.user_name or 'SYSTEM'}'."
        dedupe_key = f"{self.id}:{ev.host}"

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
                    entity="Windows Defender",
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []
