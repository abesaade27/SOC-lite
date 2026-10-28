"""Execution, LOLBins, and process tree detection rules: SOC-007, SOC-008, and SOC-013."""

import base64
import re
from typing import List
from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..state import StateStore, parse_iso_ts

POWERSHELL_PROC_REGEX = re.compile(r"(powershell\.exe|pwsh\.exe)", re.IGNORECASE)
POWERSHELL_ENC_REGEX = re.compile(r"\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
POWERSHELL_OBFUSC_REGEX = re.compile(
    r"(?=.*-nop)(?=.*-w\s+hidden)(?=.*(?:IEX|Invoke-Expression|DownloadString))", re.IGNORECASE
)

LOLBIN_PATTERNS = [
    (re.compile(r"certutil.*-urlcache", re.IGNORECASE), "certutil download via urlcache"),
    (re.compile(r"bitsadmin.*/transfer", re.IGNORECASE), "bitsadmin background file transfer"),
    (re.compile(r"mshta.*https?://", re.IGNORECASE), "mshta remote HTML application execution"),
    (re.compile(r"regsvr32.*(?:/i:https?://|scrobj\.dll)", re.IGNORECASE), "regsvr32 proxy script execution"),
    (re.compile(r"rundll32.*javascript:", re.IGNORECASE), "rundll32 inline javascript execution"),
    (
        re.compile(r"(?:curl|wget).*https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE),
        "curl/wget direct IP download",
    ),
]

OFFICE_PARENTS = re.compile(r"(winword\.exe|excel\.exe|outlook\.exe|powerpnt\.exe)", re.IGNORECASE)
SUSP_CHILDREN = re.compile(r"(cmd\.exe|powershell\.exe|pwsh\.exe|wscript\.exe|cscript\.exe|mshta\.exe)", re.IGNORECASE)


class SOC007EncodedPowerShell(Rule):
    id = "SOC-007"
    name = "Encoded / obfuscated PowerShell"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "T1059.001"
    description = "PowerShell executed with Base64 encoded or obfuscated inline script parameters."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id not in (4688, 1):
            return []

        proc = ev.process_name or ""
        cmd = ev.command_line or ""
        if not (POWERSHELL_PROC_REGEX.search(proc) or POWERSHELL_PROC_REGEX.search(cmd)):
            return []

        decoded_preview = ""
        matched = False

        enc_match = POWERSHELL_ENC_REGEX.search(cmd)
        if enc_match:
            matched = True
            b64_str = enc_match.group(1)
            try:
                # PowerShell uses UTF-16LE encoding for -EncodedCommand
                decoded_bytes = base64.b64decode(b64_str)
                decoded_text = decoded_bytes.decode("utf-16le", errors="ignore").strip()
                decoded_preview = f" [Decoded: {decoded_text[:200]}]"
            except Exception:
                decoded_preview = " [Failed to decode base64]"
        elif POWERSHELL_OBFUSC_REGEX.search(cmd):
            matched = True
            decoded_preview = " [Obfuscated download/execution cradle]"

        if not matched:
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        desc = (
            f"PowerShell executed with encoded/obfuscated command line by user '{ev.user_name or 'SYSTEM'}': "
            f"{cmd[:150]}...{decoded_preview}"
        )
        dedupe_key = f"{self.id}:{ev.host}:{ev.user_name or 'user'}"

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
                    entity=ev.user_name or "powershell.exe",
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC008LOLBinAbuse(Rule):
    id = "SOC-008"
    name = "LOLBin abuse for download / proxy execution"
    severity = Severity.HIGH
    mitre_tactic = "Defense Evasion"
    mitre_technique = "T1218"
    description = "Living Off the Land Binary (LOLBin) executed with patterns typical of file download or script proxying."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id not in (4688, 1):
            return []

        cmd = ev.command_line or ""
        if not cmd:
            return []

        matched_pattern = None
        for pat, label in LOLBIN_PATTERNS:
            if pat.search(cmd):
                matched_pattern = label
                break

        if not matched_pattern:
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        desc = (
            f"Suspicious LOLBin execution detected ({matched_pattern}) by user '{ev.user_name or 'SYSTEM'}': "
            f"{cmd[:250]}"
        )
        dedupe_key = f"{self.id}:{ev.host}:{matched_pattern}"

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
                    entity=ev.process_name or "LOLBin",
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC013SuspiciousParentChild(Rule):
    id = "SOC-013"
    name = "Suspicious parent-child process"
    severity = Severity.HIGH
    mitre_tactic = "Execution"
    mitre_technique = "T1204.002"
    description = "Microsoft Office application spawned an unexpected script interpreter or shell process."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if ev.event_id not in (4688, 1):
            return []

        parent = (ev.parent_process or "").split("\\")[-1]
        child = (ev.process_name or "").split("\\")[-1]

        if OFFICE_PARENTS.search(parent) and SUSP_CHILDREN.search(child):
            ts_float = parse_iso_ts(ev.timestamp)
            desc = (
                f"Suspicious process tree: Office application '{parent}' spawned shell process '{child}' "
                f"with command line: {ev.command_line or child}"
            )
            dedupe_key = f"{self.id}:{ev.host}:{parent}->{child}"

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
                        entity=f"{parent}->{child}",
                        description=desc,
                        event_uids=[ev.event_uid],
                        dedupe_key=dedupe_key,
                    )
                ]
        return []
