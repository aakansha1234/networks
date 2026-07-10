"""Vendor config parsers. Each turns raw text into a normalized Device."""
from __future__ import annotations

from ..model import Device

# cheap vendor autodetect — expanded as more parsers land
_IOS_HINTS = ("interface ", "hostname ", "ip access-list", "snmp-server", "line vty")
_PANOS_HINTS = ("set deviceconfig", "set network interface", "set rulebase",
                "set zone", "set shared")


def detect_vendor(text: str) -> str:
    if any(h in text for h in _PANOS_HINTS):
        return "paloalto"
    if any(h in text for h in _IOS_HINTS):
        return "cisco"
    return "cisco"  # default; warn in CLI


def parse(text: str) -> Device:
    """Parse a config, autodetecting the vendor."""
    vendor = detect_vendor(text)
    if vendor == "paloalto":
        from .panos import parse as parse_panos
        return parse_panos(text)
    from .ios import parse as parse_ios
    return parse_ios(text)
