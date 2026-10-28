"""Windows Event XML Normalizer producing canonical SOC-Lite events."""

from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _parse_int(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    val = value.strip()
    if not val or val == "-":
        return None
    try:
        if val.lower().startswith("0x"):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return None


def _clean_str(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    val = str(value).strip()
    return None if val in ("", "-", "%%1793", "NULL") else val


def _clean_ip(value: Optional[str]) -> Optional[str]:
    ip = _clean_str(value)
    if not ip:
        return None
    if ip == "::1":
        return "127.0.0.1"
    return ip


def _format_timestamp(ts_str: Optional[str]) -> str:
    if not ts_str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    ts_str = ts_str.strip()
    try:
        if ts_str.endswith("Z"):
            dt = datetime.fromisoformat(ts_str[:-1]).replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_event_xml(xml_content: str, host_override: Optional[str] = None) -> Optional[Dict[str, Any]]:
    try:
        root = ET.fromstring(xml_content)
    except Exception:
        return None

    system = root.find("e:System", NS)
    if system is None:
        system = root.find("System")
        local_ns = {}
    else:
        local_ns = NS

    prefix = "e:" if local_ns else ""

    def get_sys_text(tag: str) -> Optional[str]:
        el = system.find(f"{prefix}{tag}", local_ns) if system is not None else None
        return el.text if el is not None else None

    provider_el = system.find(f"{prefix}Provider", local_ns) if system is not None else None
    provider = provider_el.attrib.get("Name") if provider_el is not None else None

    time_created_el = system.find(f"{prefix}TimeCreated", local_ns) if system is not None else None
    sys_time = time_created_el.attrib.get("SystemTime") if time_created_el is not None else None
    timestamp = _format_timestamp(sys_time)

    event_id = _parse_int(get_sys_text("EventID")) or 0
    record_id = _parse_int(get_sys_text("EventRecordID")) or 0
    level = _parse_int(get_sys_text("Level")) or 0
    channel = _clean_str(get_sys_text("Channel")) or "Security"
    computer = host_override or _clean_str(get_sys_text("Computer")) or "UNKNOWN-HOST"

    # Extract raw data
    raw: Dict[str, str] = {}
    event_data = root.find(f"{prefix}EventData", local_ns)
    if event_data is not None:
        for data in event_data.findall(f"{prefix}Data", local_ns):
            name = data.attrib.get("Name")
            text = data.text or ""
            if name:
                raw[name] = text
            elif text:
                raw[f"param_{len(raw)+1}"] = text

    user_data = root.find(f"{prefix}UserData", local_ns)
    if user_data is not None:
        for child in user_data:
            for sub in child:
                tag_name = sub.tag.split("}")[-1]
                raw[tag_name] = sub.text or ""

    uid_source = f"{computer}|{channel}|{record_id}"
    event_uid = hashlib.sha1(uid_source.encode("utf-8")).hexdigest()

    category = "other"
    action = f"event_{event_id}"
    user_name = None
    user_domain = None
    target_user = None
    src_ip = None
    src_port = None
    dst_ip = None
    dst_port = None
    logon_type = None
    process_name = None
    process_id = None
    parent_process = None
    command_line = None
    summary = f"Event {event_id} in {channel}"

    # Field mappings per spec
    if channel == "Security":
        if event_id == 4624:
            category = "auth"
            action = "logon_success"
            user_name = _clean_str(raw.get("TargetUserName"))
            user_domain = _clean_str(raw.get("TargetDomainName"))
            logon_type = _parse_int(raw.get("LogonType"))
            src_ip = _clean_ip(raw.get("IpAddress"))
            src_port = _parse_int(raw.get("IpPort"))
            process_name = _clean_str(raw.get("ProcessName"))
            summary = f"Successful logon for {user_name or 'unknown'} from {src_ip or 'local'} (type {logon_type or '?'})"

        elif event_id == 4625:
            category = "auth"
            action = "logon_failure"
            user_name = _clean_str(raw.get("TargetUserName"))
            user_domain = _clean_str(raw.get("TargetDomainName"))
            logon_type = _parse_int(raw.get("LogonType"))
            src_ip = _clean_ip(raw.get("IpAddress"))
            src_port = _parse_int(raw.get("IpPort"))
            process_name = _clean_str(raw.get("ProcessName"))
            summary = f"Failed logon for {user_name or 'unknown'} from {src_ip or 'local'} (type {logon_type or '?'})"

        elif event_id in (4634, 4647):
            category = "auth"
            action = "logoff"
            user_name = _clean_str(raw.get("TargetUserName"))
            logon_type = _parse_int(raw.get("LogonType"))
            summary = f"Logoff for {user_name or 'unknown'}"

        elif event_id == 4648:
            category = "auth"
            action = "explicit_credentials"
            user_name = _clean_str(raw.get("SubjectUserName"))
            target_user = _clean_str(raw.get("TargetUserName"))
            src_ip = _clean_ip(raw.get("IpAddress"))
            process_name = _clean_str(raw.get("ProcessName"))
            summary = f"Explicit credentials used by {user_name} targeting {target_user}"

        elif event_id == 4672:
            category = "auth"
            action = "special_privileges"
            user_name = _clean_str(raw.get("SubjectUserName"))
            summary = f"Special privileges assigned to {user_name}"

        elif event_id == 4688:
            category = "process"
            action = "process_create"
            user_name = _clean_str(raw.get("SubjectUserName"))
            process_name = _clean_str(raw.get("NewProcessName"))
            process_id = _parse_int(raw.get("NewProcessId"))
            parent_process = _clean_str(raw.get("ParentProcessName"))
            command_line = _clean_str(raw.get("CommandLine"))
            summary = f"Process created: {process_name or 'unknown'} by {user_name or 'SYSTEM'}"

        elif event_id in (4697,):
            category = "service"
            action = "service_install"
            process_name = _clean_str(raw.get("ServiceFileName") or raw.get("ImagePath"))
            summary = f"Service installed: {raw.get('ServiceName', 'unknown')} ({process_name})"

        elif event_id == 4698:
            category = "task"
            action = "scheduled_task_created"
            user_name = _clean_str(raw.get("SubjectUserName"))
            task_name = raw.get("TaskName", "unknown")
            summary = f"Scheduled task created: {task_name} by {user_name}"

        elif event_id == 4720:
            category = "account"
            action = "user_created"
            user_name = _clean_str(raw.get("SubjectUserName"))
            target_user = _clean_str(raw.get("TargetUserName"))
            summary = f"User account created: {target_user} by {user_name}"

        elif event_id in (4722, 4725, 4726):
            category = "account"
            actions = {4722: "user_enabled", 4725: "user_disabled", 4726: "user_deleted"}
            action = actions[event_id]
            user_name = _clean_str(raw.get("SubjectUserName"))
            target_user = _clean_str(raw.get("TargetUserName"))
            summary = f"User account {action}: {target_user} by {user_name}"

        elif event_id == 4724:
            category = "account"
            action = "password_reset"
            user_name = _clean_str(raw.get("SubjectUserName"))
            target_user = _clean_str(raw.get("TargetUserName"))
            summary = f"Password reset for {target_user} by {user_name}"

        elif event_id in (4728, 4732, 4756):
            category = "account"
            action = "group_member_added"
            user_name = _clean_str(raw.get("SubjectUserName"))
            target_user = _clean_str(raw.get("MemberName") or raw.get("MemberSid"))
            group_name = raw.get("TargetUserName") or raw.get("TargetSid") or "group"
            summary = f"Member {target_user} added to group {group_name} by {user_name}"

        elif event_id == 4740:
            category = "account"
            action = "account_lockout"
            target_user = _clean_str(raw.get("TargetUserName"))
            summary = f"Account locked out: {target_user}"

        elif event_id == 1102:
            category = "policy"
            action = "audit_log_cleared"
            user_name = _clean_str(raw.get("SubjectUserName"))
            summary = f"Security audit log cleared by {user_name or 'SYSTEM'}"

    elif channel == "System":
        if event_id == 7045:
            category = "service"
            action = "service_install"
            process_name = _clean_str(raw.get("ImagePath"))
            summary = f"Service installed: {raw.get('ServiceName', 'unknown')} ({process_name})"
        elif event_id == 104:
            category = "policy"
            action = "audit_log_cleared"
            user_name = _clean_str(raw.get("UserName") or raw.get("SubjectUserName"))
            summary = f"System event log cleared by {user_name or 'SYSTEM'}"

    elif "PowerShell" in channel:
        if event_id == 4104:
            category = "powershell"
            action = "script_block"
            script_text = raw.get("ScriptBlockText", "")
            if len(script_text) > 8000:
                command_line = script_text[:8000]
                raw["truncated"] = "true"
            else:
                command_line = script_text
            summary = f"PowerShell script block executed ({len(command_line)} chars)"

    elif "Sysmon" in channel:
        if event_id == 1:
            category = "process"
            action = "process_create"
            process_name = _clean_str(raw.get("Image"))
            command_line = _clean_str(raw.get("CommandLine"))
            parent_process = _clean_str(raw.get("ParentImage"))
            user_name = _clean_str(raw.get("User"))
            process_id = _parse_int(raw.get("ProcessId"))
            summary = f"Sysmon process create: {process_name} by {user_name}"
        elif event_id == 3:
            category = "network"
            action = "network_connect"
            process_name = _clean_str(raw.get("Image"))
            src_ip = _clean_ip(raw.get("SourceIp"))
            src_port = _parse_int(raw.get("SourcePort"))
            dst_ip = _clean_ip(raw.get("DestinationIp"))
            dst_port = _parse_int(raw.get("DestinationPort"))
            user_name = _clean_str(raw.get("User"))
            summary = f"Network connection: {process_name} -> {dst_ip}:{dst_port}"
        elif event_id == 10:
            category = "process"
            action = "process_access"
            process_name = _clean_str(raw.get("SourceImage"))
            summary = f"Process access by {process_name} to {raw.get('TargetImage')}"
        elif event_id == 11:
            category = "other"
            action = "file_create"
            process_name = _clean_str(raw.get("Image"))
            summary = f"File created by {process_name}: {raw.get('TargetFilename')}"
        elif event_id == 13:
            category = "other"
            action = "registry_set"
            process_name = _clean_str(raw.get("Image"))
            summary = f"Registry modified by {process_name}: {raw.get('TargetObject')}"

    elif "Defender" in channel:
        if event_id in (5001, 5010, 5012):
            category = "defender"
            action = "protection_disabled"
            summary = f"Defender protection disabled (Event {event_id})"
        elif event_id in (1116, 1117):
            category = "defender"
            action = "malware_detected" if event_id == 1116 else "malware_action"
            summary = f"Defender detected threat: {raw.get('ThreatName', 'Unknown')}"

    return {
        "event_uid": event_uid,
        "timestamp": timestamp,
        "host": computer,
        "channel": channel,
        "provider": provider,
        "event_id": event_id,
        "record_id": record_id,
        "level": level,
        "category": category,
        "action": action,
        "user_name": user_name,
        "user_domain": user_domain,
        "target_user": target_user,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "logon_type": logon_type,
        "process_name": process_name,
        "process_id": process_id,
        "parent_process": parent_process,
        "command_line": command_line,
        "summary": summary,
        "raw": raw,
    }
