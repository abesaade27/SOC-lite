"""Tests for Windows Event XML normalization."""

import pytest
from agent.normalizer import normalize_event_xml

SAMPLE_4625_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4625</EventID>
    <Level>0</Level>
    <EventRecordID>99100</EventRecordID>
    <Channel>Security</Channel>
    <Computer>LAB-WIN10</Computer>
    <TimeCreated SystemTime="2026-10-27T17:05:12.345Z" />
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
    <Data Name="TargetDomainName">LAB-WIN10</Data>
    <Data Name="Status">0xC000006D</Data>
    <Data Name="SubStatus">0xC000006A</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">192.168.1.100</Data>
    <Data Name="IpPort">51234</Data>
  </EventData>
</Event>
"""

SAMPLE_4688_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <Level>0</Level>
    <EventRecordID>99101</EventRecordID>
    <Channel>Security</Channel>
    <Computer>LAB-WIN10</Computer>
    <TimeCreated SystemTime="2026-10-27T17:06:00.000Z" />
  </System>
  <EventData>
    <Data Name="SubjectUserName">bob</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="NewProcessId">0x1a4c</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>
"""

SAMPLE_1102_XML = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" />
    <EventID>1102</EventID>
    <Level>4</Level>
    <EventRecordID>99102</EventRecordID>
    <Channel>Security</Channel>
    <Computer>LAB-WIN10</Computer>
    <TimeCreated SystemTime="2026-10-27T17:07:00.000Z" />
  </System>
  <UserData>
    <LogFileCleared>
      <SubjectUserName>admin</SubjectUserName>
    </LogFileCleared>
  </UserData>
</Event>
"""


def test_normalize_4625() -> None:
    ev = normalize_event_xml(SAMPLE_4625_XML)
    assert ev is not None
    assert ev["event_id"] == 4625
    assert ev["category"] == "auth"
    assert ev["action"] == "logon_failure"
    assert ev["user_name"] == "alice"
    assert ev["src_ip"] == "192.168.1.100"
    assert ev["src_port"] == 51234
    assert ev["logon_type"] == 3
    assert "99100" in ev["event_uid"] or len(ev["event_uid"]) == 40


def test_normalize_4688_hex_pid() -> None:
    ev = normalize_event_xml(SAMPLE_4688_XML)
    assert ev is not None
    assert ev["event_id"] == 4688
    assert ev["category"] == "process"
    assert ev["process_id"] == 6732  # 0x1a4c == 6732
    assert ev["command_line"] == "cmd.exe /c whoami"
    assert ev["user_name"] == "bob"


def test_normalize_1102_userdata() -> None:
    ev = normalize_event_xml(SAMPLE_1102_XML)
    assert ev is not None
    assert ev["event_id"] == 1102
    assert ev["category"] == "policy"
    assert ev["action"] == "audit_log_cleared"
    assert ev["user_name"] == "admin"
