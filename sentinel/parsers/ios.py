"""Cisco IOS / IOS-XE config parser.

IOS configs are `!`-separated sections. The first non-`!` line of a section is
either a context header (interface / ip access-list / line / router / ...) whose
indented children belong to it, or a standalone global command. We group lines
into sections, then dispatch on the header token.

This is intentionally pragmatic: it covers the constructs the detection rules
need (interfaces, ACLs, SNMP, lines, crypto/services) rather than every knob in
IOS. Gaps are explicit and easy to extend.
"""
from __future__ import annotations

import re

from ..model import (
    ACL,
    ACLEntry,
    Device,
    Interface,
    LineConfig,
    SNMPCommunity,
)

_NET_RE = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


def parse(text: str) -> Device:
    device = Device(vendor="cisco", os="ios")
    raw_lines = text.splitlines()
    device.config_lines = raw_lines

    for section in _sectionize(raw_lines):
        if not section:
            continue
        _, header = section[0]
        tokens = header.split()
        first = tokens[0] if tokens else ""

        if first == "interface":
            _parse_interface(device, section)
        elif header.startswith("ip access-list"):
            _parse_named_acl(device, section)
        elif first == "line":
            _parse_line(device, section)
        elif first in ("router", "control-plane", "policy-map", "class-map"):
            pass  # out of scope for milestone 1
        else:
            # standalone globals — possibly several per section
            for ln, line in section:
                _parse_global(device, ln, line)
    return device


def _sectionize(lines: list[str]) -> list[list[tuple[int, str]]]:
    """Split on `!` / `end`; keep (line_no, stripped_line) tuples."""
    sections: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for i, raw in enumerate(lines, 1):
        s = raw.strip()
        if s == "" :
            continue
        if s.startswith("!"):  # separator or comment line
            if current:
                sections.append(current)
                current = []
            continue
        if s == "end":
            break
        current.append((i, s))
    if current:
        sections.append(current)
    return sections


# -- global commands ----------------------------------------------------------

def _parse_global(device: Device, ln: int, line: str) -> None:
    t = line.split()
    if not t:
        return
    head = t[0]
    if head == "hostname" and len(t) > 1:
        device.hostname = t[1]
    elif head == "version" and len(t) > 1:
        device.version = t[1]
    elif line.startswith("snmp-server community"):
        _parse_snmp(device, ln, line)
    elif line.startswith("ip ssh version") and t[-1].isdigit():
        device.ssh_version = int(t[-1])
    elif line == "ip http server":
        device.http_server = True
    elif line == "no ip http server":
        device.http_server = False
    elif line == "ip http secure-server":
        device.https_server = True
    elif line == "service password-encryption":
        device.password_encryption = True
    elif line == "no service password-encryption":
        device.password_encryption = False
    elif line == "ip source-route":
        device.source_route = True
    elif line == "no ip source-route":
        device.source_route = False
    elif head == "logging":
        # 'logging host A.B.C.D' (modern) or legacy 'logging A.B.C.D'
        ip = t[2] if len(t) >= 3 and t[1] == "host" else (t[1] if len(t) > 1 else "")
        if ip and _NET_RE.fullmatch(ip):
            device.logging_hosts.append(ip)
    elif line.startswith("ntp server") and len(t) > 2:
        device.ntp_servers.append(t[2])
    elif head == "username" and len(t) > 1:
        device.local_users.append(t[1])
    elif head.startswith("banner"):
        device.banner = True
    elif head == "access-list":
        _parse_numbered_acl(device, ln, line)


# -- contexts -----------------------------------------------------------------

def _parse_interface(device: Device, section: list[tuple[int, str]]) -> None:
    hln, header = section[0]
    t = header.split()
    iface = Interface(name=t[1] if len(t) > 1 else "unknown", line=hln, shutdown=True)
    for ln, line in section[1:]:
        tt = line.split()
        if not tt:
            continue
        if tt[0] == "ip" and len(tt) >= 3 and tt[1] == "address":
            iface.ip_address = tt[2]
            iface.subnet_mask = tt[3] if len(tt) >= 4 else None
        elif tt[0] == "description":
            iface.description = " ".join(tt[1:])
        elif line == "shutdown":
            iface.shutdown = True
        elif line == "no shutdown":
            iface.shutdown = False
        elif tt[0] == "switchport" and len(tt) >= 4 and tt[2] == "vlan":
            try:
                iface.vlan = int(tt[3])
            except ValueError:
                pass
        elif tt[0] == "ip" and len(tt) >= 4 and tt[1] == "access-group":
            if tt[3] == "in":
                iface.access_group_in = tt[2]
            elif tt[3] == "out":
                iface.access_group_out = tt[2]
        elif line == "cdp enable":
            iface.cdp_enabled = True
        elif line == "no cdp enable":
            iface.cdp_enabled = False
    device.interfaces.append(iface)


def _parse_named_acl(device: Device, section: list[tuple[int, str]]) -> None:
    hln, header = section[0]
    t = header.split()
    # ip access-list {extended|standard} NAME
    kind = t[2] if len(t) >= 3 else "extended"
    name = t[3] if len(t) >= 4 else "unknown"
    acl = ACL(name=name, kind=kind, line=hln)
    for ln, line in section[1:]:
        if line.split()[:1] == ["remark"]:
            continue
        entry = _parse_acl_entry(ln, line, kind)
        if entry:
            acl.entries.append(entry)
    device.acls.append(acl)


def _parse_numbered_acl(device: Device, ln: int, line: str) -> None:
    # access-list 101 permit tcp any any eq 443
    t = line.split()
    if len(t) < 4:
        return
    name = t[1]
    num = int(name) if name.isdigit() else 0
    kind = "standard" if (1 <= num <= 99 or 1300 <= num <= 1999) else "extended"
    acl = device.acl(name)
    if acl is None:
        acl = ACL(name=name, kind=kind, line=ln)
        device.acls.append(acl)
    entry = _parse_acl_entry(ln, " ".join(t[2:]), kind)
    if entry:
        acl.entries.append(entry)


def _parse_acl_entry(ln: int, line: str, kind: str) -> ACLEntry | None:
    t = line.split()
    if len(t) < 3 or t[0] not in ("permit", "deny"):
        return None
    action = t[0]
    if kind == "standard":
        # permit <src> — protocol implicit
        src, idx = _parse_addr(t, 1)
        return ACLEntry(action=action, protocol="ip", source=src, dest="any",
                        raw=line, line=ln)
    protocol = t[1]
    idx = 2
    src, idx = _parse_addr(t, idx)
    dest, idx = _parse_addr(t, idx)
    entry = ACLEntry(action=action, protocol=protocol, source=src, dest=dest,
                     raw=line, line=ln)
    rest = t[idx:]
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in ("eq", "gt", "lt", "neq") and i + 1 < len(rest):
            entry.dst_port = f"{tok} {rest[i + 1]}"
            i += 2
        elif tok == "established":
            entry.established = True
            i += 1
        elif tok == "log":
            entry.log = True
            i += 1
        else:
            i += 1
    return entry


def _parse_addr(t: list[str], idx: int) -> tuple[str, int]:
    if idx >= len(t):
        return ("any", idx)
    tok = t[idx]
    if tok == "any":
        return ("any", idx + 1)
    if tok == "host" and idx + 1 < len(t):
        return (f"host {t[idx + 1]}", idx + 2)
    # network <ip> <wildcard>
    if idx + 1 < len(t) and _NET_RE.fullmatch(t[idx + 1]):
        return (f"{t[idx]} {t[idx + 1]}", idx + 2)
    return (tok, idx + 1)


def _parse_snmp(device: Device, ln: int, line: str) -> None:
    # snmp-server community NAME [RO|RW] [ACL] [view VIEW]
    t = line.split()
    if len(t) < 3:
        return
    name = t[2]
    access = "RO"
    for tok in t[3:]:
        if tok in ("RO", "RW"):
            access = tok
            break
    device.snmp.append(SNMPCommunity(name=name, access=access, line=ln))


def _parse_line(device: Device, section: list[tuple[int, str]]) -> None:
    # A section may contain several 'line' blocks when '!' was omitted between
    # them (common in pasted configs). A new 'line' header opens a new block.
    current: LineConfig | None = None
    for ln, line in section:
        t = line.split()
        if not t:
            continue
        if t[0] == "line":
            current = LineConfig(name=t[1] if len(t) > 1 else "unknown", line=ln)
            device.lines.append(current)
            continue
        if current is None:
            continue
        if t[0] == "transport" and len(t) >= 3 and t[1] == "input":
            current.transport_input = t[2:]
        elif t[0] == "login":
            current.login = t[1] if len(t) > 1 else ""
        elif t[0] == "no" and len(t) > 1 and t[1] == "login":
            current.login = "none"
        elif t[0] == "password":
            current.password_present = True
            current.password_type = int(t[1]) if len(t) > 1 and t[1].isdigit() else 0
        elif t[0] == "access-class" and len(t) >= 3:
            current.access_class = f"{t[1]} {t[2]}"
