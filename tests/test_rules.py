from pathlib import Path

from sentinel.parsers.ios import parse
from sentinel.rules import run

FIX = Path(__file__).parent / "fixtures"


def _findings(name: str):
    device = parse((FIX / name).read_text())
    return run(device)


def test_clean_config_has_no_findings():
    assert _findings("clean_router.cfg") == []


def test_bad_config_finds_expected_rules():
    ids = {f.rule_id for f in _findings("bad_router.cfg")}
    expected = {
        "IOS-SNMP-001", "IOS-SNMP-002",
        "IOS-ACCESS-001", "IOS-ACCESS-003", "IOS-ACCESS-004",
        "IOS-MGMT-001", "IOS-MGMT-002", "IOS-MGMT-003",
        "IOS-CRYPTO-001", "IOS-CRYPTO-002",
        "IOS-ACL-001", "IOS-ROUTE-001",
    }
    missing = expected - ids
    assert not missing, f"missing rules: {missing}"


def test_rw_default_community_is_critical():
    findings = _findings("bad_router.cfg")
    crit = [f for f in findings if f.rule_id == "IOS-SNMP-001"
            and "private" in f.evidence]
    assert crit and crit[0].severity.value == "critical"


def test_findings_cite_evidence_and_lines():
    findings = [f for f in _findings("bad_router.cfg") if f.line is not None]
    assert len(findings) >= 5
    assert all(f.evidence.strip() for f in findings)


def test_remediation_is_actionable():
    findings = _findings("bad_router.cfg")
    assert all(f.remediation.strip() for f in findings)


def test_remediation_script_dedups():
    from sentinel.remediate import remediation_script
    script = remediation_script(_findings("bad_router.cfg"), "branch-rtr-01")
    assert "configure terminal" in script
    assert script.splitlines().count("end") == 1
    assert "no snmp-server community public" in script
    assert "service password-encryption" in script
