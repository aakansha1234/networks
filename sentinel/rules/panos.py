"""Palo Alto PAN-OS detection rules.

Mirror the security-posture angle of the IOS rules but in firewall-policy terms:
over-permissive security rules, missing logging, App-ID bypass, internet-facing
allows, and a silent implicit default-deny. Each finding cites the rule name.
"""
from __future__ import annotations

from ..finding import Finding, Severity
from ..model import Device, SecurityRule
from . import register


def _is_any(rule: SecurityRule, field: str) -> bool:
    return "any" in getattr(rule, field)


@register("panos")
def any_any_allow(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for r in device.security_rules:
        if (r.action == "allow" and _is_any(r, "sources")
                and _is_any(r, "destinations") and _is_any(r, "applications")
                and _is_any(r, "services")):
            out.append(Finding(
                rule_id="PAN-RULE-001",
                title=f"Security rule '{r.name}' allows ANY/ANY/ANY/ANY",
                severity=Severity.CRITICAL,
                category="policy",
                description=("A catch-all allow rule makes the firewall a piece "
                             "of wire: any source, destination, application, and "
                             "service is permitted. This defeats App-ID, User-ID, "
                             "and all segmentation intent."),
                evidence=f"rule '{r.name}': allow any->any src any dst any app any svc any",
                line=r.line,
                remediation=(f"delete rulebase security {r.name}\n"
                             "! replace with least-privilege rules bound to "
                             "specific source/destination address objects, "
                             "applications, and services."),
            ))
    return out


@register("panos")
def allow_without_logging(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for r in device.security_rules:
        if r.action == "allow" and not r.log_end:
            out.append(Finding(
                rule_id="PAN-RULE-002",
                title=f"Allow rule '{r.name}' does not log at session end",
                severity=Severity.MEDIUM,
                category="policy",
                description=("Without log-end you have no record of what traffic "
                             "this rule actually passed — blind spots for forensics "
                             "and compliance."),
                evidence=f"rule '{r.name}': action allow, log-end not set",
                line=r.line,
                remediation=f"set rulebase security {r.name} log-end yes",
            ))
    return out


@register("panos")
def allow_app_any(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for r in device.security_rules:
        if r.action == "allow" and _is_any(r, "applications"):
            out.append(Finding(
                rule_id="PAN-RULE-003",
                title=f"Allow rule '{r.name}' permits application 'any' (App-ID bypass)",
                severity=Severity.HIGH,
                category="policy",
                description=("App-ID is the core value of a next-gen firewall. "
                             "Allowing 'application any' means policy is enforced "
                             "on ports/IPs only — indistinguishable from a legacy "
                             "firewall, and trivially evaded by port-hopping."),
                evidence=f"rule '{r.name}': application any",
                line=r.line,
                remediation=(f"set rulebase security {r.name} application "
                             "<specific-apps>   ! e.g. web-browsing ssl"),
            ))
    return out


@register("panos")
def untrust_source_any(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for r in device.security_rules:
        if r.action != "allow":
            continue
        internet_facing = ("any" in r.from_zones) or ("untrust" in r.from_zones)
        if internet_facing and _is_any(r, "sources"):
            out.append(Finding(
                rule_id="PAN-RULE-004",
                title=f"Internet-facing allow rule '{r.name}' matches source 'any'",
                severity=Severity.HIGH,
                category="policy",
                description=("The rule matches traffic from the internet (untrust) "
                             "with no source restriction — any host on the public "
                             "internet can attempt the allowed service."),
                evidence=(f"rule '{r.name}': from {r.from_zones} source any"),
                line=r.line,
                remediation=(f"set rulebase security {r.name} source "
                             "<specific-address-objects>"),
            ))
    return out


@register("panos")
def no_logged_default_deny(device: Device) -> list[Finding]:
    has_logged_deny = any(
        r.action in ("deny", "drop", "reset-client", "reset-server", "reset-both")
        and r.log_end for r in device.security_rules
    )
    if device.security_rules and not has_logged_deny:
        return [Finding(
            rule_id="PAN-RULE-005",
            title="No explicit, logged default-deny rule in the security rulebase",
            severity=Severity.LOW,
            category="policy",
            description=("PAN-OS applies an implicit deny after the last rule, but "
                         "it does not log. Without an explicit logged deny you "
                         "cannot see what the firewall is blocking."),
            evidence="(no rule with action deny/drop and log-end yes)",
            remediation=("set rulebase security default-deny from any to any "
                         "source any destination any application any service "
                         "application-default action deny log-end yes"),
        )]
    return []
