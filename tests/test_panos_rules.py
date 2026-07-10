from pathlib import Path

from sentinel.parsers.panos import parse
from sentinel.rules import run

FIX = Path(__file__).parent / "fixtures"


def _findings(name: str):
    return run(parse((FIX / name).read_text()))


def test_clean_panos_config_has_no_findings():
    assert _findings("pa_fw_clean.cfg") == []


def test_bad_panos_config_finds_expected_rules():
    ids = {f.rule_id for f in _findings("pa_fw_bad.cfg")}
    expected = {"PAN-RULE-001", "PAN-RULE-002", "PAN-RULE-003",
                "PAN-RULE-004", "PAN-RULE-005"}
    assert expected.issubset(ids), ids - expected


def test_any_any_rule_is_critical():
    findings = _findings("pa_fw_bad.cfg")
    crit = [f for f in findings if f.rule_id == "PAN-RULE-001"]
    assert crit and crit[0].severity.value == "critical"


def test_app_any_flagged_on_multiple_rules():
    findings = [f for f in _findings("pa_fw_bad.cfg") if f.rule_id == "PAN-RULE-003"]
    # allow-any-any and allow-rdp both have application any
    assert len(findings) >= 2


def test_panos_findings_have_remediation():
    findings = _findings("pa_fw_bad.cfg")
    assert all(f.remediation.strip() for f in findings)
