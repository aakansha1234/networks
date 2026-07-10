from pathlib import Path

from sentinel.agent import (
    _strip_fences,
    ask,
    device_context,
    findings_context,
    generate_remediation,
    lint_config_delta,
)
from sentinel.parsers.ios import parse
from sentinel.rules import run

FIX = Path(__file__).parent / "fixtures"


class FakeClient:
    """Records the prompt, returns a canned response — no network."""
    def __init__(self, response: str = "ok"):
        self.response = response
        self.last_system = ""
        self.last_user = ""

    def complete(self, system, user, *, temperature=0.2, max_tokens=1024):
        self.last_system = system
        self.last_user = user
        return self.response


def _device():
    d = parse((FIX / "bad_router.cfg").read_text())
    return d, run(d)


# -- grounding ----------------------------------------------------------------

def test_device_context_is_compact_and_factual():
    d, _ = _device()
    ctx = device_context(d)
    assert "branch-rtr-01" in ctx
    assert "OUTSIDE-IN" in ctx and "permit ip any any" in ctx
    assert "POSTURE:" in ctx
    assert "password_encryption=off" in ctx
    assert "ssh_version=1" in ctx
    assert "public(RO)" in ctx  # SNMP folded in


def test_findings_context_lists_findings():
    _, findings = _device()
    ctx = findings_context(findings)
    assert "FINDINGS" in ctx
    assert "IOS-SNMP-001" in ctx


# -- config syntax guard ------------------------------------------------------

def test_lint_catches_prose_leak():
    delta = "no snmp-server community public\nSure! Here is the fix.\nip ssh version 2"
    issues = lint_config_delta(delta)
    assert (2, "Sure! Here is the fix.") in issues
    assert len(issues) == 1


def test_lint_passes_clean_config():
    delta = "configure terminal\nno ip http server\nservice password-encryption\nend"
    assert lint_config_delta(delta) == []


def test_strip_fences():
    assert _strip_fences("```ios\nfoo\n```") == "foo"
    assert _strip_fences("```\nfoo\n```") == "foo"
    assert _strip_fences("foo") == "foo"


# -- operations (fake model) --------------------------------------------------

def test_ask_feeds_device_context_to_model():
    d, findings = _device()
    fake = FakeClient("because telnet + default SNMP")
    out = ask(d, findings, "why is this device risky?", fake)
    assert out == "because telnet + default SNMP"
    assert "branch-rtr-01" in fake.last_user       # device facts sent
    assert "FINDINGS" in fake.last_user             # scanner output sent
    assert "why is this device risky?" in fake.last_user


def test_generate_remediation_returns_clean_delta():
    d, _ = _device()
    fake = FakeClient("no snmp-server community public\nend")
    delta, issues = generate_remediation(d, "remove the public community", fake)
    assert "no snmp-server community public" in delta
    assert issues == []


def test_generate_remediation_flags_leaked_prose():
    d, _ = _device()
    fake = FakeClient("Here you go:\nno snmp-server community public")
    delta, issues = generate_remediation(d, "remove public community", fake)
    assert issues  # "Here you go:" is not an IOS verb
