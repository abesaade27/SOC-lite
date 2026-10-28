"""Deterministic sample data generator for SOC-Lite."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import random

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE_DATA_DIR = os.path.join(BASE_DIR, "sample_data")


def make_uid(host: str, channel: str, record_id: int) -> str:
    return hashlib.sha1(f"{host}|{channel}|{record_id}".encode("utf-8")).hexdigest()


def generate_attack_scenario() -> None:
    events = []
    host = "LAB-WIN10"
    attacker_ip = "192.168.56.101"
    start_time = datetime(2026, 10, 27, 18, 0, 0, tzinfo=timezone.utc)
    curr_time = start_time
    rec_id = 10000

    def get_ts() -> str:
        return curr_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # Step 1: 20 failed logons (4625) from 192.168.56.101 targeting alice, bob, admin (Fires SOC-001)
    target_users = ["alice", "bob", "admin", "administrator", "guest"]
    for i in range(20):
        curr_time += timedelta(seconds=2)
        rec_id += 1
        t_user = target_users[i % len(target_users)]
        uid = make_uid(host, "Security", rec_id)
        events.append({
            "event_uid": uid,
            "timestamp": get_ts(),
            "host": host,
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "record_id": rec_id,
            "level": 0,
            "category": "auth",
            "action": "logon_failure",
            "user_name": t_user,
            "user_domain": host,
            "target_user": t_user,
            "src_ip": attacker_ip,
            "src_port": 49152 + i,
            "dst_ip": "192.168.56.10",
            "dst_port": 445,
            "logon_type": 3,
            "process_name": None,
            "process_id": None,
            "parent_process": None,
            "command_line": None,
            "summary": f"Failed logon for {t_user} from {attacker_ip} (type 3)",
            "raw": {"IpAddress": attacker_ip, "TargetUserName": t_user, "SubStatus": "0xC000006A"},
        })

    # Step 2: 1 successful logon (4624 type 3) for admin (Fires SOC-002)
    curr_time += timedelta(seconds=5)
    rec_id += 1
    uid = make_uid(host, "Security", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4624,
        "record_id": rec_id,
        "level": 0,
        "category": "auth",
        "action": "logon_success",
        "user_name": "admin",
        "user_domain": host,
        "target_user": "admin",
        "src_ip": attacker_ip,
        "src_port": 49175,
        "dst_ip": "192.168.56.10",
        "dst_port": 445,
        "logon_type": 3,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": f"Successful logon for admin from {attacker_ip} (type 3)",
        "raw": {"IpAddress": attacker_ip, "TargetUserName": "admin", "LogonType": "3"},
    })

    # Step 3: Discovery commands (whoami /all and net user)
    discovery_cmds = [
        ("C:\\Windows\\System32\\whoami.exe", "whoami /all"),
        ("C:\\Windows\\System32\\net.exe", "net user"),
    ]
    for p_name, cmd in discovery_cmds:
        curr_time += timedelta(seconds=4)
        rec_id += 1
        uid = make_uid(host, "Security", rec_id)
        events.append({
            "event_uid": uid,
            "timestamp": get_ts(),
            "host": host,
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4688,
            "record_id": rec_id,
            "level": 0,
            "category": "process",
            "action": "process_create",
            "user_name": "admin",
            "user_domain": host,
            "target_user": None,
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "logon_type": None,
            "process_name": p_name,
            "process_id": 4512,
            "parent_process": "C:\\Windows\\System32\\cmd.exe",
            "command_line": cmd,
            "summary": f"Process created: {p_name} by admin",
            "raw": {"NewProcessName": p_name, "CommandLine": cmd, "SubjectUserName": "admin"},
        })

    # Step 4: Create new user svc_backup$ (4720) (Fires SOC-003)
    curr_time += timedelta(seconds=6)
    rec_id += 1
    uid = make_uid(host, "Security", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4720,
        "record_id": rec_id,
        "level": 0,
        "category": "account",
        "action": "user_created",
        "user_name": "admin",
        "user_domain": host,
        "target_user": "svc_backup$",
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": "User account created: svc_backup$ by admin",
        "raw": {"TargetUserName": "svc_backup$", "SubjectUserName": "admin"},
    })

    # Step 5: Add svc_backup$ to Administrators (4732) (Fires SOC-004 and SOC-014 correlation)
    curr_time += timedelta(seconds=8)
    rec_id += 1
    uid = make_uid(host, "Security", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4732,
        "record_id": rec_id,
        "level": 0,
        "category": "account",
        "action": "group_member_added",
        "user_name": "admin",
        "user_domain": host,
        "target_user": "svc_backup$",
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": "Member svc_backup$ added to group Administrators by admin",
        "raw": {
            "MemberName": "svc_backup$",
            "TargetUserName": "Administrators",
            "TargetSid": "S-1-5-32-544",
            "SubjectUserName": "admin",
        },
    })

    # Step 6: Encoded PowerShell execution (Fires SOC-007)
    curr_time += timedelta(seconds=10)
    rec_id += 1
    raw_ps_payload = "Write-Host 'SOC-Lite Attack Simulation Payload Test'"
    b64_ps = base64.b64encode(raw_ps_payload.encode("utf-16le")).decode("utf-8")
    ps_cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {b64_ps}"
    uid = make_uid(host, "Security", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4688,
        "record_id": rec_id,
        "level": 0,
        "category": "process",
        "action": "process_create",
        "user_name": "admin",
        "user_domain": host,
        "target_user": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process_id": 5120,
        "parent_process": "C:\\Windows\\System32\\cmd.exe",
        "command_line": ps_cmd,
        "summary": "Process created: powershell.exe by admin",
        "raw": {
            "NewProcessName": "powershell.exe",
            "CommandLine": ps_cmd,
            "SubjectUserName": "admin",
        },
    })

    # Step 7: New service in C:\Users\Public\ (7045) (Fires SOC-006)
    curr_time += timedelta(seconds=12)
    rec_id += 1
    uid = make_uid(host, "System", rec_id)
    svc_image = "C:\\Users\\Public\\updater_svc.exe"
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "System",
        "provider": "Service Control Manager",
        "event_id": 7045,
        "record_id": rec_id,
        "level": 0,
        "category": "service",
        "action": "service_install",
        "user_name": "SYSTEM",
        "user_domain": None,
        "target_user": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": svc_image,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": f"Service installed: WindowsHealthUpdater ({svc_image})",
        "raw": {
            "ServiceName": "WindowsHealthUpdater",
            "ImagePath": svc_image,
            "ServiceType": "user mode service",
        },
    })

    # Step 8: Scheduled task created (4698) (Fires SOC-009)
    curr_time += timedelta(seconds=14)
    rec_id += 1
    uid = make_uid(host, "Security", rec_id)
    task_xml = "<Task><Actions><Exec><Command>powershell.exe -w hidden -enc abc</Command></Exec></Actions></Task>"
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 4698,
        "record_id": rec_id,
        "level": 0,
        "category": "task",
        "action": "scheduled_task_created",
        "user_name": "admin",
        "user_domain": host,
        "target_user": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": "Scheduled task created: PersistentCheck by admin",
        "raw": {
            "TaskName": "PersistentCheck",
            "TaskContent": task_xml,
            "SubjectUserName": "admin",
        },
    })

    # Step 9: Sysmon 10 LSASS memory access by C:\Users\Public\x.exe (Fires SOC-010)
    curr_time += timedelta(seconds=16)
    rec_id += 1
    uid = make_uid(host, "Microsoft-Windows-Sysmon/Operational", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "provider": "Microsoft-Windows-Sysmon",
        "event_id": 10,
        "record_id": rec_id,
        "level": 0,
        "category": "process",
        "action": "process_access",
        "user_name": "admin",
        "user_domain": host,
        "target_user": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": "C:\\Users\\Public\\x.exe",
        "process_id": 6124,
        "parent_process": None,
        "command_line": None,
        "summary": "Process access by C:\\Users\\Public\\x.exe to C:\\Windows\\System32\\lsass.exe",
        "raw": {
            "SourceImage": "C:\\Users\\Public\\x.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0x9f4a",
        },
    })

    # Step 10: Security audit log cleared (1102) (Fires SOC-005)
    curr_time += timedelta(seconds=20)
    rec_id += 1
    uid = make_uid(host, "Security", rec_id)
    events.append({
        "event_uid": uid,
        "timestamp": get_ts(),
        "host": host,
        "channel": "Security",
        "provider": "Microsoft-Windows-Security-Auditing",
        "event_id": 1102,
        "record_id": rec_id,
        "level": 0,
        "category": "policy",
        "action": "audit_log_cleared",
        "user_name": "admin",
        "user_domain": host,
        "target_user": None,
        "src_ip": None,
        "src_port": None,
        "dst_ip": None,
        "dst_port": None,
        "logon_type": None,
        "process_name": None,
        "process_id": None,
        "parent_process": None,
        "command_line": None,
        "summary": "Security audit log cleared by admin",
        "raw": {"SubjectUserName": "admin"},
    })

    out_file = os.path.join(SAMPLE_DATA_DIR, "attack_scenario.jsonl")
    with open(out_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Generated attack scenario with {len(events)} events: {out_file}")


def generate_benign_baseline() -> None:
    random.seed(42)
    events = []
    hosts = ["DESKTOP-FIN01", "DESKTOP-HR02", "SERVER-FS01", "SERVER-DC01"]
    users = ["alice", "bob", "charlie", "david", "emma", "frank"]
    start_time = datetime(2026, 10, 27, 8, 0, 0, tzinfo=timezone.utc)
    curr_time = start_time
    rec_id = 1000

    for i in range(500):
        curr_time += timedelta(seconds=random.randint(1, 15))
        rec_id += 1
        host = random.choice(hosts)
        user = random.choice(users)
        channel = "Security"

        eid = random.choice([4624, 4634, 4672, 4688])
        if eid == 4624:
            cat, act = "auth", "logon_success"
            summary = f"Successful logon for {user} from local (type 2)"
            raw = {"TargetUserName": user, "LogonType": "2"}
        elif eid == 4634:
            cat, act = "auth", "logoff"
            summary = f"Logoff for {user}"
            raw = {"TargetUserName": user, "LogonType": "2"}
        elif eid == 4672:
            cat, act = "auth", "special_privileges"
            summary = f"Special privileges assigned to {user}"
            raw = {"SubjectUserName": user}
        else:
            cat, act = "process", "process_create"
            proc = random.choice([
                "C:\\Windows\\explorer.exe",
                "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                "C:\\Windows\\System32\\svchost.exe",
            ])
            summary = f"Process created: {proc} by {user}"
            raw = {"NewProcessName": proc, "SubjectUserName": user}

        events.append({
            "event_uid": make_uid(host, channel, rec_id),
            "timestamp": curr_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "host": host,
            "channel": channel,
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": eid,
            "record_id": rec_id,
            "level": 0,
            "category": cat,
            "action": act,
            "user_name": user,
            "user_domain": "CORP",
            "target_user": None,
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "logon_type": 2 if eid in (4624, 4634) else None,
            "process_name": raw.get("NewProcessName"),
            "process_id": random.randint(1000, 8000) if eid == 4688 else None,
            "parent_process": "C:\\Windows\\explorer.exe" if eid == 4688 else None,
            "command_line": None,
            "summary": summary,
            "raw": raw,
        })

    out_file = os.path.join(SAMPLE_DATA_DIR, "benign_baseline.jsonl")
    with open(out_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    print(f"Generated benign baseline with {len(events)} events: {out_file}")


if __name__ == "__main__":
    os.makedirs(SAMPLE_DATA_DIR, exist_ok=True)
    generate_attack_scenario()
    generate_benign_baseline()
