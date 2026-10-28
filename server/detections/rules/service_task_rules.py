"""Service and scheduled task persistence detection rules: SOC-006 and SOC-009."""

import os
import re
from typing import Any, Dict, List, Optional
import yaml

from server.models import Event
from ..authenticode import is_signed_by_vendor, verify_authenticode
from ..base import AlertPayload, Rule, Severity
from ..state import StateStore, parse_iso_ts

SUSPICIOUS_SVC_PATHS = re.compile(
    r"(\\temp\\|\\appdata\\|\\users\\public\\|cmd\.exe\s+/c|powershell)", re.IGNORECASE
)
STANDARD_WINDOWS_PATHS = re.compile(
    r"^(?:[a-zA-Z]:\\(?:Windows|Program Files|Program Files \(x86\))\\)", re.IGNORECASE
)

# Default whitelist fallback if not found in config
DEFAULT_WHITELIST = {
    "vendor_paths": [
        "googleupdate.exe",
        "msedgeupdate.exe",
        "\\appdata\\local\\microsoft\\onedrive",
        "\\appdata\\local\\microsoft\\teams",
        "\\appdata\\local\\zoom",
    ],
    "parent_processes": [
        "googleupdate.exe",
        "msedgeupdate.exe",
    ],
    "trusted_signers": [
        "Google LLC",
        "Microsoft Corporation",
        "Zoom Video Communications, Inc.",
    ],
}


def load_whitelist_config() -> Dict[str, Any]:
    cfg_path = os.path.join(os.path.dirname(__file__), "..", "rules.yaml")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                return data.get("whitelist_service_task", DEFAULT_WHITELIST)
        except Exception:
            pass
    return DEFAULT_WHITELIST


def is_service_task_whitelisted(
    image_path: str,
    parent_process: Optional[str] = None,
    raw: Optional[Dict[str, Any]] = None,
) -> bool:
    """Checks if service or task matches whitelist AND is validly signed by a trusted vendor."""
    cfg = load_whitelist_config()
    vendor_paths = [p.lower() for p in cfg.get("vendor_paths", [])]
    parent_procs = [p.lower() for p in cfg.get("parent_processes", [])]
    trusted_signers = cfg.get("trusted_signers", [])

    img_lower = image_path.lower()
    parent_lower = (parent_process or "").lower()

    matches_path = any(vp in img_lower for vp in vendor_paths)
    matches_parent = any(pp in parent_lower for pp in parent_procs)

    if not (matches_path or matches_parent):
        return False

    # "Whitelist only when the signature is valid."
    sig = verify_authenticode(image_path, raw=raw)
    if not sig.get("is_valid"):
        return False

    signer = sig.get("signer") or ""
    return any(ts.lower() in signer.lower() for ts in trusted_signers)


class SOC006NewServiceInstalled(Rule):
    id = "SOC-006"
    name = "New service installed"
    severity = Severity.MEDIUM
    mitre_tactic = "Persistence"
    mitre_technique = "T1543.003"
    description = "A new service was registered on the system."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        if not (
            (ev.channel == "System" and ev.event_id == 7045)
            or (ev.channel == "Security" and ev.event_id == 4697)
        ):
            return []

        svc_name = ev.raw.get("ServiceName", "unknown")
        image_path = ev.process_name or ev.raw.get("ImagePath") or ev.raw.get("ServiceFileName") or ""
        ts_float = parse_iso_ts(ev.timestamp)

        # Configurable whitelist check (GoogleUpdate, EdgeUpdate, OneDrive, Teams, Zoom)
        if is_service_task_whitelisted(image_path, ev.parent_process, raw=ev.raw):
            return []

        severity = self.severity
        notes = []

        # Check Authenticode signature: suppress suspicious-path alert if validly signed by Microsoft/Google
        # unless command line contains known malicious arguments
        is_signed_ms_google = is_signed_by_vendor(image_path, ("Microsoft", "Google"), raw=ev.raw)

        if SUSPICIOUS_SVC_PATHS.search(image_path):
            if is_signed_ms_google and not re.search(r"(cmd\.exe\s+/c|powershell)", image_path, re.IGNORECASE):
                # Suppressed because validly signed Microsoft/Google binary without malicious args
                pass
            else:
                severity = Severity.HIGH
                notes.append("contains suspicious directory or script interpreter")
        elif image_path and not STANDARD_WINDOWS_PATHS.match(image_path):
            if not is_signed_ms_google:
                severity = Severity.HIGH
                notes.append("installed outside standard system directories")

        notes_str = f" [{'; '.join(notes)}]" if notes else ""
        desc = f"New service '{svc_name}' installed with binary path '{image_path}'{notes_str}."
        dedupe_key = f"{self.id}:{ev.host}:{svc_name.lower()}"

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
                    entity=svc_name,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []


class SOC009ScheduledTaskCreated(Rule):
    id = "SOC-009"
    name = "Scheduled task created"
    severity = Severity.MEDIUM
    mitre_tactic = "Persistence"
    mitre_technique = "T1053.005"
    description = "A new scheduled task was registered on the host."
    cooldown_seconds = 60

    def evaluate(self, ev: Event, state: StateStore) -> List[AlertPayload]:
        is_4698 = ev.channel == "Security" and ev.event_id == 4698
        is_schtasks_cmd = False

        if ev.event_id in (4688, 1) and ev.command_line:
            pname = (ev.process_name or "").lower()
            if "schtasks" in pname and "/create" in ev.command_line.lower():
                is_schtasks_cmd = True

        if not (is_4698 or is_schtasks_cmd):
            return []

        task_name = ev.raw.get("TaskName") or "schtasks_command"
        task_content = ev.raw.get("TaskContent") or ev.command_line or ""
        ts_float = parse_iso_ts(ev.timestamp)

        # Configurable whitelist check (GoogleUpdate, EdgeUpdate, OneDrive, Teams, Zoom)
        if is_service_task_whitelisted(task_content, ev.parent_process, raw=ev.raw):
            return []

        severity = self.severity
        notes = []
        if re.search(r"(powershell|cmd\.exe|mshta|wscript|cscript)", task_content, re.IGNORECASE):
            severity = Severity.HIGH
            notes.append("task executes shell/scripting interpreter")

        notes_str = f" [{'; '.join(notes)}]" if notes else ""
        desc = f"Scheduled task created: '{task_name}' by user '{ev.user_name or 'SYSTEM'}'{notes_str}."
        dedupe_key = f"{self.id}:{ev.host}:{task_name.lower()}"

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
                    entity=task_name,
                    description=desc,
                    event_uids=[ev.event_uid],
                    dedupe_key=dedupe_key,
                )
            ]
        return []
