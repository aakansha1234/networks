"""Palo Alto PAN-OS config parser (set-command format).

PAN-OS exports configs as XML or as a flat list of `set` commands. We parse the
set-command form — line-oriented and what operators type/paste. XML-export
support is a noted future extension.

Security rules are accumulated across multiple `set rulebase security <name>
<key> <values...>` lines into a single SecurityRule, and we tolerate the keys
appearing on one combined line as well.
"""
from __future__ import annotations

import ipaddress

from ..model import Device, Interface, SecurityRule, Service, Zone

_RULE_KEYS = {
    "from", "to", "source", "destination", "application", "service",
    "action", "log-end", "log-start", "description",
}


def parse(text: str) -> Device:
    device = Device(vendor="paloalto", os="panos")
    raw = text.splitlines()
    device.config_lines = raw
    rules: dict[str, SecurityRule] = {}
    for ln, line in enumerate(raw, 1):
        s = line.strip()
        if not s or s.startswith(("#", "!")):
            continue
        if not s.startswith("set "):
            continue
        _parse_set(device, rules, ln, s.split()[1:])
    device.security_rules = list(rules.values())
    return device


def _parse_set(device: Device, rules: dict[str, SecurityRule],
               ln: int, t: list[str]) -> None:
    head = t[0] if t else ""
    if head == "deviceconfig":
        _deviceconfig(device, ln, t[1:])
    elif head == "network" and len(t) > 1 and t[1] == "interface":
        _interface(device, ln, t[2:])
    elif head == "zone":
        _zone(device, ln, t[1:])
    elif head == "address":
        _address(device, ln, t[1:])
    elif head == "service":
        _service(device, ln, t[1:])
    elif head == "rulebase" and len(t) > 1 and t[1] == "security":
        _security_rule(rules, ln, t[2:])


def _deviceconfig(device: Device, ln: int, t: list[str]) -> None:
    if len(t) >= 3 and t[0] == "system":
        if t[1] == "hostname":
            device.hostname = t[2]
        elif t[1] == "ip-address":
            device.mgmt_ip = t[2]


def _interface(device: Device, ln: int, t: list[str]) -> None:
    # t = [type, name, "layer3", "ip", cidr, ...]
    if len(t) < 2:
        return
    iface = Interface(name=t[1], line=ln, shutdown=False)
    if "ip" in t:
        i = t.index("ip")
        if i + 1 < len(t):
            ip, _, prefix = t[i + 1].partition("/")
            iface.ip_address = ip
            iface.subnet_mask = _cidr_to_mask(prefix) if prefix else None
    device.interfaces.append(iface)


def _zone(device: Device, ln: int, t: list[str]) -> None:
    if len(t) < 1:
        return
    name = t[0]
    zone = next((z for z in device.zones if z.name == name), None)
    if zone is None:
        zone = Zone(name=name, line=ln)
        device.zones.append(zone)
    if "layer3" in t:
        i = t.index("layer3")
        if i + 1 < len(t):
            zone.interfaces.append(t[i + 1])


def _address(device: Device, ln: int, t: list[str]) -> None:
    if len(t) >= 3 and t[1] == "ip-netmask":
        device.addresses[t[0]] = t[2]


def _service(device: Device, ln: int, t: list[str]) -> None:
    if len(t) >= 3:
        device.services.append(Service(name=t[0], protocol=t[1], port=t[2], line=ln))


def _security_rule(rules: dict[str, SecurityRule], ln: int, t: list[str]) -> None:
    if len(t) < 2:
        return
    name = t[0]
    rule = rules.get(name)
    if rule is None:
        rule = SecurityRule(name=name, line=ln)
        rules[name] = rule

    # walk key/value groups (handles both one-key-per-line and combined lines)
    cur: str | None = None
    vals: list[str] = []

    def flush(key: str, v: list[str]) -> None:
        if key == "from":
            rule.from_zones.extend(v)
        elif key == "to":
            rule.to_zones.extend(v)
        elif key == "source":
            rule.sources.extend(v)
        elif key == "destination":
            rule.destinations.extend(v)
        elif key == "application":
            rule.applications.extend(v)
        elif key == "service":
            rule.services.extend(v)
        elif key == "action":
            rule.action = v[0] if v else rule.action
        elif key == "log-end":
            rule.log_end = bool(v and v[0] == "yes")
        elif key == "log-start":
            rule.log_start = bool(v and v[0] == "yes")

    for tok in t[1:]:
        if tok in _RULE_KEYS:
            if cur is not None:
                flush(cur, vals)
            cur, vals = tok, []
        elif cur is not None:
            vals.append(tok)
    if cur is not None:
        flush(cur, vals)


def _cidr_to_mask(prefix: str) -> str | None:
    try:
        return str(ipaddress.ip_network(f"0.0.0.0/{prefix}").netmask)
    except ValueError:
        return None
