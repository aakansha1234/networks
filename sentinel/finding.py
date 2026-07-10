"""Finding model and severity weights."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# higher = worse; used for ordering and a rough posture score
WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@dataclass
class Finding:
    rule_id: str                 # e.g. IOS-SNMP-001
    title: str
    severity: Severity
    category: str                # snmp | acl | access | crypto | mgmt | route
    description: str             # why it matters
    evidence: str                # offending config text
    line: int | None = None
    remediation: str = ""        # config delta(s) or guidance
    cis_ref: str | None = None   # CIS benchmark reference when applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "evidence": self.evidence,
            "line": self.line,
            "remediation": self.remediation,
            "cis_ref": self.cis_ref,
        }


@dataclass
class ScanResult:
    device: Any                  # model.Device (typed loosely to avoid import cycle)
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def score(self) -> int:
        """Posture score 0..100 (higher = better)."""
        penalty = sum(WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty * 4)

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: -WEIGHT[f.severity])
