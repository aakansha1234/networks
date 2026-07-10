"""Build a single apply-ready config delta script from findings."""
from __future__ import annotations

from .finding import Finding


def remediation_script(findings: list[Finding], hostname: str = "device") -> str:
    """Concatenate per-finding remediation into one config-mode script.

    Lines are de-duplicated on stripped content so repeated advice (e.g.
    'service password-encryption') collapses. Output is ordered by severity
    so the worst issues are addressed first.
    """
    ordered = sorted(findings, key=lambda f: f.severity.value)
    lines: list[str] = []
    seen: set[str] = set()
    for f in ordered:
        if not f.remediation:
            continue
        for raw in f.remediation.splitlines():
            stripped = raw.strip()
            if not stripped:
                continue
            if stripped in seen:
                continue
            seen.add(stripped)
            lines.append(raw.rstrip())
    header = [
        f"! ===== Sentinel remediation for {hostname} =====",
        f"! {len(findings)} finding(s) — review each line before applying.",
        "configure terminal",
        "!",
    ]
    return "\n".join(header + lines + ["!", "end", "! verify, then: write memory"])
