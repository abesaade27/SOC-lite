"""Endpoint specific detection rules: SOC-015 through SOC-020."""

import os
import re
from typing import Any, Dict, List, Optional
import yaml

from server.models import Event
from ..base import AlertPayload, Rule, Severity
from ..net_utils import get_network_group_key, is_non_private_ip
from ..state import StateStore, parse_iso_ts

BROWSER_PROCESSES = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe"}
BROWSER_CRED_PATTERNS = re.compile(
    r"(\\(?:Google\\Chrome|Microsoft\\Edge|Mozilla\\Firefox)\\.*\\(?:Login Data|Cookies|Web Data))",
    re.IGNORECASE,
)

RUN_KEY_PATTERN = re.compile(
    r"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\(?:Run|RunOnce)",
    re.IGNORECASE,
)

STARTUP_FOLDER_PATTERN = re.compile(
    r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    re.IGNORECASE,
)

OUTBOUND_LOLBINS = {"rundll32.exe", "powershell.exe", "pwsh.exe", "certutil.exe"}

RANSOMWARE_EXT_PATTERN = re.compile(
    r"\.(locked|crypto|enc|crypted|ransom|locky|wanacry|wncry)$",
    re.IGNORECASE,
)


def load_ioc_hashes() -> Dict[str, Any]:
    ioc_path = os.path.join(os.path.dirname(__file__), "..", "ioc_hashes.yaml")
    if os.path.exists(ioc_path):
        try:
            with open(ioc_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            pass
    return {"malicious_sha256": [], "known_imphash_tools": {}}


def parse_sysmon_hashes(hashes_str: str) -> Dict[str, str]:
    result = {}
    if not hashes_str:
        return result
    for part in hashes_str.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip().upper()] = v.strip().lower()
    return result


class SOC015BrowserCredentialTheft(Rule):
    id = "SOC-015"
    name = "Browser credential store access"
    severity = Severity.HIGH
    mitre_tactic = "Credential Access"
    mitre_technique = "T1555.003"
    description = "Non-browser process accessed or created/copied browser credential or cookie files."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon doesn't log file reads, so use Security Event 4663 if a SACL exists.
        # Otherwise detect non-browser file creation/copy of these files via Sysmon 11.
        is_4663 = ev.channel == "Security" and ev.event_id == 4663
        is_sysmon11 = "Sysmon" in ev.channel and ev.event_id == 11

        if not (is_4663 or is_sysmon11):
            return []

        target_file = ev.raw.get("ObjectName") or ev.raw.get("TargetFilename") or ""
        if not BROWSER_CRED_PATTERNS.search(target_file):
            return []

        proc_path = ev.process_name or ev.raw.get("ProcessName") or ""
        proc_base = proc_path.split("\\")[-1].lower()

        # Legitimate browsers are excluded
        if proc_base in BROWSER_PROCESSES:
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        desc = (
            f"Suspicious access to browser credential database by non-browser process '{proc_base}': "
            f"Target file: {target_file}"
        )
        dedupe_key = f"{self.id}:{ev.host}:{proc_base}"

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
                    entity=f"{proc_base} -> {os.path.basename(target_file)}",
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC016RunKeyPersistence(Rule):
    id = "SOC-016"
    name = "HKCU/HKLM Run-key persistence modified"
    severity = Severity.HIGH
    mitre_tactic = "Persistence"
    mitre_technique = "T1547.001"
    description = "A registry run or run-once key was created or modified to maintain persistence."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 13: RegistryEvent (Value Set)
        if not ("Sysmon" in ev.channel and ev.event_id == 13):
            return []

        target_obj = ev.raw.get("TargetObject") or ""
        if not RUN_KEY_PATTERN.search(target_obj):
            return []

        proc_path = ev.process_name or ""
        proc_base = proc_path.split("\\")[-1] or "Unknown"
        details = ev.raw.get("Details") or ""
        ts_float = parse_iso_ts(ev.timestamp)

        desc = (
            f"Registry Run-key persistence configured by process '{proc_base}': "
            f"Key: {target_obj} [Value: {details}]"
        )
        dedupe_key = f"{self.id}:{ev.host}:{target_obj.lower()}"

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
                    entity=target_obj,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC017StartupFolderDrop(Rule):
    id = "SOC-017"
    name = "Startup folder file drop"
    severity = Severity.HIGH
    mitre_tactic = "Persistence"
    mitre_technique = "T1547.001"
    description = "A new file or script was created in the Windows Startup directory."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 11: FileCreate
        if not ("Sysmon" in ev.channel and ev.event_id == 11):
            return []

        target_file = ev.raw.get("TargetFilename") or ""
        if not STARTUP_FOLDER_PATTERN.search(target_file):
            return []

        proc_path = ev.process_name or ""
        proc_base = proc_path.split("\\")[-1] or "Unknown"
        ts_float = parse_iso_ts(ev.timestamp)

        desc = (
            f"File created in Startup folder by process '{proc_base}': "
            f"{target_file}"
        )
        dedupe_key = f"{self.id}:{ev.host}:{target_file.lower()}"

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
                    entity=os.path.basename(target_file),
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC018OutboundLOLBinConnection(Rule):
    id = "SOC-018"
    name = "Outbound external connection from script host or LOLBin"
    severity = Severity.HIGH
    mitre_tactic = "Command and Control"
    mitre_technique = "T1105"
    description = "rundll32, powershell, or certutil established an external outbound network connection."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 3: Network connection
        if not ("Sysmon" in ev.channel and ev.event_id == 3):
            return []

        proc_path = ev.process_name or ""
        proc_base = proc_path.split("\\")[-1].lower()
        if proc_base not in OUTBOUND_LOLBINS:
            return []

        # Exclude private, loopback, and local IPs
        dst_ip = ev.dst_ip or ev.raw.get("DestinationIp") or ""
        if not is_non_private_ip(dst_ip):
            return []

        ts_float = parse_iso_ts(ev.timestamp)
        dst_port = ev.dst_port or ev.raw.get("DestinationPort") or "?"
        net_group = get_network_group_key(dst_ip, ev.raw)

        desc = (
            f"External outbound network connection established by '{proc_base}': "
            f"Destination {dst_ip}:{dst_port} ({net_group})"
        )
        dedupe_key = f"{self.id}:{ev.host}:{proc_base}:{net_group}"

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
                    entity=f"{proc_base} -> {dst_ip}:{dst_port}",
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC019RansomwareCanary(Rule):
    id = "SOC-019"
    name = "Ransomware canary file activity burst"
    severity = Severity.CRITICAL
    mitre_tactic = "Impact"
    mitre_technique = "T1486"
    description = "Rapid file modification or creation burst with known ransomware extensions."
    cooldown_seconds = 300
    threshold = 50
    window_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 11: FileCreate / rename
        if not ("Sysmon" in ev.channel and ev.event_id == 11):
            return []

        target_file = ev.raw.get("TargetFilename") or ""
        if not RANSOMWARE_EXT_PATTERN.search(target_file):
            return []

        ts_float = parse_iso_ts(ev.timestamp)

        # Laptop lifecycle: pause rate-based evaluation for 5 seconds after sleep resume
        if state.is_resume_paused(ts_float):
            return []

        proc_id = ev.process_id or ev.raw.get("ProcessId") or 0
        proc_name = (ev.process_name or "").split("\\")[-1] or "Unknown"
        group_key = f"{ev.host}:{proc_id}:{proc_name}"

        window = state.get_window(self.id, max_retention=300)
        window.add(ts_float, group_key, ev.event_uid, {"file": target_file})

        count, uids, metas = window.count_within(group_key, ts_float, self.window_seconds)
        dedupe_key = f"{self.id}:{group_key}"

        if count >= self.threshold and not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
            state.record_alert(dedupe_key, ts_float)
            desc = (
                f"Ransomware activity detected: Process '{proc_name}' (PID {proc_id}) created/renamed "
                f"{count} files with encrypted extensions in {self.window_seconds}s."
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
                    entity=f"{proc_name} (PID {proc_id})",
                    description=desc,
                    event_uids=uids,
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC020IOCMatchedOrRenamedTool(Rule):
    id = "SOC-020"
    name = "Malicious hash match or renamed tool"
    severity = Severity.CRITICAL
    mitre_tactic = "Defense Evasion"
    mitre_technique = "T1036.003"
    description = "Binary SHA256 matched a known IOC or IMPHASH signature indicates a renamed malicious tool."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        # Sysmon Event ID 1: Process Create
        if not ("Sysmon" in ev.channel and ev.event_id == 1):
            return []

        hashes_raw = ev.raw.get("Hashes", "")
        if not hashes_raw:
            return []

        hashes = parse_sysmon_hashes(hashes_raw)
        sha256 = hashes.get("SHA256", "").lower()
        imphash = hashes.get("IMPHASH", "").lower()

        ioc_data = load_ioc_hashes()
        malicious_hashes = [h.lower() for h in ioc_data.get("malicious_sha256", [])]
        known_imphash = {k.lower(): v.lower() for k, v in ioc_data.get("known_imphash_tools", {}).items()}

        proc_path = ev.process_name or ""
        proc_base = proc_path.split("\\")[-1].lower()
        ts_float = parse_iso_ts(ev.timestamp)

        # 1. Check SHA256 match
        if sha256 and sha256 in malicious_hashes:
            dedupe_key = f"{self.id}:{ev.host}:sha256:{sha256}"
            if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
                state.record_alert(dedupe_key, ts_float)
                desc = (
                    f"Process '{proc_base}' matched known malicious SHA256 hash IOC: {sha256}. "
                    f"Command: {ev.command_line or proc_base}"
                )
                return [
                    AlertPayload(
                        rule_id=self.id,
                        rule_name=self.name,
                        severity=self.severity,
                        mitre_tactic="Execution",
                        mitre_technique="T1204",
                        host=ev.host,
                        ts=ev.timestamp,
                        entity=f"{proc_base} (SHA256:{sha256[:12]})",
                        description=desc,
                        event_uids=[ev.event_uid],
                        dedupe_key=dedupe_key,
                    )
                ]

        # 2. Check IMPHASH mismatch (renamed tool)
        if imphash and imphash in known_imphash:
            expected_tool = known_imphash[imphash]
            if proc_base != expected_tool:
                dedupe_key = f"{self.id}:{ev.host}:imphash:{imphash}"
                if not state.is_in_cooldown(dedupe_key, ts_float, self.cooldown_seconds):
                    state.record_alert(dedupe_key, ts_float)
                    desc = (
                        f"Renamed tool detected via IMPHASH signature: Process '{proc_base}' "
                        f"has IMPHASH '{imphash}' characteristic of '{expected_tool}'."
                    )
                    return [
                        AlertPayload(
                            rule_id=self.id,
                            rule_name="Renamed tool detected (IMPHASH mismatch)",
                            severity=self.severity,
                            mitre_tactic="Defense Evasion",
                            mitre_technique="T1036.003",
                            host=ev.host,
                            ts=ev.timestamp,
                            entity=f"{proc_base} (masquerading as {expected_tool})",
                            description=desc,
                            event_uids=[ev.event_uid],
                            dedupe_key=dedupe_key,
                        )
                    ]

        return []
