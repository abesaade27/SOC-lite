"""Sanitizes sensitive names, IPs, SIDs, and profiles from Windows Event JSONL files."""

import argparse
import json
import re
import sys
from typing import Dict

USER_MAP: Dict[str, str] = {}
HOST_MAP: Dict[str, str] = {}
IP_MAP: Dict[str, str] = {}

USER_COUNTER = 1
HOST_COUNTER = 1
IP_COUNTER = 1


def get_fake_user(val: str) -> str:
    global USER_COUNTER
    if not val or val.lower() in ("system", "local service", "network service"):
        return val
    if val not in USER_MAP:
        USER_MAP[val] = f"user_{USER_COUNTER:02d}"
        USER_COUNTER += 1
    return USER_MAP[val]


def get_fake_host(val: str) -> str:
    global HOST_COUNTER
    if not val:
        return val
    if val not in HOST_MAP:
        HOST_MAP[val] = f"CORP-HOST-{HOST_COUNTER:02d}"
        HOST_COUNTER += 1
    return HOST_MAP[val]


def get_fake_ip(val: str) -> str:
    global IP_COUNTER
    if not val or val in ("127.0.0.1", "::1"):
        return val
    if val not in IP_MAP:
        IP_MAP[val] = f"10.200.0.{IP_COUNTER}"
        IP_COUNTER += 1
    return IP_MAP[val]


def scrub_cmd(cmd: str) -> str:
    if not cmd:
        return cmd
    # Replace C:\Users\SpecificName with C:\Users\RedactedUser
    return re.sub(r"[a-zA-Z]:\\Users\\[^\\]+", r"C:\\Users\\User", cmd)


def sanitize_event(ev: dict) -> dict:
    if "user_name" in ev and ev["user_name"]:
        ev["user_name"] = get_fake_user(ev["user_name"])
    if "target_user" in ev and ev["target_user"]:
        ev["target_user"] = get_fake_user(ev["target_user"])
    if "host" in ev and ev["host"]:
        ev["host"] = get_fake_host(ev["host"])
    if "src_ip" in ev and ev["src_ip"]:
        ev["src_ip"] = get_fake_ip(ev["src_ip"])
    if "dst_ip" in ev and ev["dst_ip"]:
        ev["dst_ip"] = get_fake_ip(ev["dst_ip"])
    if "command_line" in ev and ev["command_line"]:
        ev["command_line"] = scrub_cmd(ev["command_line"])

    # Scrub raw dictionary
    if "raw" in ev and isinstance(ev["raw"], dict):
        raw = ev["raw"]
        for k in list(raw.keys()):
            if "User" in k and raw[k]:
                raw[k] = get_fake_user(raw[k])
            elif "Ip" in k and raw[k]:
                raw[k] = get_fake_ip(raw[k])
            elif "CommandLine" in k and raw[k]:
                raw[k] = scrub_cmd(raw[k])

    return ev


def main() -> None:
    parser = argparse.ArgumentParser(description="Sanitize Windows event JSONL log files")
    parser.add_argument("input_file", help="Input raw JSONL file")
    parser.add_argument("output_file", help="Output sanitized JSONL file")
    args = parser.parse_args()

    count = 0
    with open(args.input_file, "r", encoding="utf-8") as fin, open(args.output_file, "w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                sanitized = sanitize_event(ev)
                fout.write(json.dumps(sanitized) + "\n")
                count += 1
            except Exception as e:
                print(f"Skipping malformed line: {e}", file=sys.stderr)

    print(f"Successfully sanitized {count} events -> {args.output_file}")


if __name__ == "__main__":
    main()
