from pathlib import Path

from sentinel.parsers.panos import parse

FIX = Path(__file__).parent / "fixtures"


def test_parses_identity_and_interfaces():
    d = parse((FIX / "pa_fw_bad.cfg").read_text())
    assert d.hostname == "pa-fw-01"
    assert d.vendor == "paloalto" and d.os == "panos"
    assert d.mgmt_ip == "10.0.0.1"
    names = [i.name for i in d.interfaces]
    assert names == ["ethernet1/1", "ethernet1/2"]
    assert d.interfaces[0].ip_address == "203.0.113.2"
    assert d.interfaces[0].subnet_mask == "255.255.255.0"  # /24 converted


def test_parses_zones_addresses_services():
    d = parse((FIX / "pa_fw_bad.cfg").read_text())
    assert {z.name for z in d.zones} == {"untrust", "trust"}
    untrust = next(z for z in d.zones if z.name == "untrust")
    assert untrust.interfaces == ["ethernet1/1"]
    assert d.addresses == {"server-1": "192.168.1.10/32"}
    assert d.services[0].name == "web-443"
    assert d.services[0].protocol == "tcp" and d.services[0].port == "443"


def test_parses_security_rules_with_fields():
    d = parse((FIX / "pa_fw_bad.cfg").read_text())
    by_name = {r.name: r for r in d.security_rules}
    assert set(by_name) == {"allow-any-any", "allow-rdp", "allow-web"}
    anyany = by_name["allow-any-any"]
    assert anyany.from_zones == ["any"] and anyany.sources == ["any"]
    assert anyany.action == "allow" and anyany.log_end is False
    rdp = by_name["allow-rdp"]
    assert rdp.from_zones == ["untrust"] and rdp.log_end is True
    assert rdp.services == ["application-default"]


def test_autodetect_routes_panos_via_dispatch():
    from sentinel.parsers import parse as dispatch, detect_vendor
    text = (FIX / "pa_fw_bad.cfg").read_text()
    assert detect_vendor(text) == "paloalto"
    d = dispatch(text)
    assert d.os == "panos"
