from pathlib import Path

from sentinel.parsers.ios import parse

FIX = Path(__file__).parent / "fixtures"


def test_parses_hostname_and_version():
    d = parse((FIX / "bad_router.cfg").read_text())
    assert d.hostname == "branch-rtr-01"
    assert d.version == "15.7"
    assert d.vendor == "cisco" and d.os == "ios"


def test_parses_interfaces():
    d = parse((FIX / "bad_router.cfg").read_text())
    names = [i.name for i in d.interfaces]
    assert names == ["GigabitEthernet0/0", "GigabitEthernet0/1", "Vlan1"]
    wan = d.interfaces[0]
    assert wan.ip_address == "203.0.113.2"
    assert wan.subnet_mask == "255.255.255.252"
    assert wan.access_group_in == "OUTSIDE-IN"
    assert wan.shutdown is False
    assert d.interfaces[2].shutdown is True  # Vlan1 shut


def test_parses_acl_entries():
    d = parse((FIX / "bad_router.cfg").read_text())
    acl = d.acl("OUTSIDE-IN")
    assert acl is not None and acl.kind == "extended"
    assert len(acl.entries) == 2
    any_any = acl.entries[1]
    assert any_any.action == "permit"
    assert any_any.source == "any" and any_any.dest == "any"
    # first entry keeps a bound destination
    assert acl.entries[0].dest.startswith("host")


def test_parses_snmp_vty_ssh_posture():
    d = parse((FIX / "bad_router.cfg").read_text())
    assert [c.name for c in d.snmp] == ["public", "private"]
    assert d.snmp[0].access == "RO" and d.snmp[1].access == "RW"
    vty = next(l for l in d.lines if l.name == "vty")
    assert vty.transport_input == ["telnet", "ssh"]
    assert vty.password_present and vty.password_type == 7
    assert d.ssh_version == 1
    assert d.http_server is True
    assert d.password_encryption is False
    assert d.source_route is True
