"""Language-model interface over the parsed device.

The model is given a compact structured summary of the parsed :class:`Device`
and the scanner findings (not the raw config), and returns either a plain-text
answer or a config delta. Config deltas are linted against known IOS commands so
non-config output is flagged before display.
"""
from __future__ import annotations

from dataclasses import asdict

from .finding import Finding
from .llm import LLMClient
from .model import Device

# -- device context (passed to the model) -------------------------------------

def device_context(device: Device) -> str:
    """Compact summary of the device, used as model context."""
    lines = [
        f"DEVICE: {device.hostname} ({device.vendor} {device.os} {device.version or ''})",
        "INTERFACES:",
    ]
    for i in device.interfaces:
        state = "shutdown" if i.shutdown else "up"
        ip = f"{i.ip_address} {i.subnet_mask}" if i.ip_address else "no-ip"
        acl = f" acl-in:{i.access_group_in}" if i.access_group_in else ""
        lines.append(f"  - {i.name}  {ip}  [{state}]{acl}")
    if device.acls:
        lines.append("ACLs:")
        for acl in device.acls:
            lines.append(f"  - {acl.name} ({acl.kind}):")
            for e in acl.entries:
                port = f" {e.dst_port}" if e.dst_port else ""
                lines.append(f"      {e.action} {e.protocol} {e.source} {e.dest}{port}")
    if device.snmp:
        lines.append("SNMP: " + ", ".join(f"{c.name}({c.access})" for c in device.snmp))
    vty = next((l for l in device.lines if l.name == "vty"), None)
    if vty:
        pw = f" password(type {vty.password_type})" if vty.password_present else " no-line-password"
        ac = f" access-class={vty.access_class}" if vty.access_class else " no-access-class"
        lines.append(f"MGMT: vty transport={vty.transport_input} login={vty.login!r}{pw}{ac}")
    if device.zones:
        lines.append("ZONES: " + ", ".join(
            f"{z.name}[{','.join(z.interfaces) or 'no-if'}]" for z in device.zones))
    if device.addresses:
        lines.append("ADDRS: " + ", ".join(f"{n}={c}" for n, c in device.addresses.items()))
    if device.security_rules:
        lines.append("SECURITY RULES:")
        for r in device.security_rules:
            apps = ",".join(r.applications) or "-"
            svcs = ",".join(r.services) or "-"
            lines.append(
                f"  - {r.name}: {r.action} {','.join(r.from_zones)}->"
                f"{','.join(r.to_zones)} src={','.join(r.sources)} "
                f"dst={','.join(r.destinations)} app={apps} svc={svcs} "
                f"log_end={'yes' if r.log_end else 'no'}"
            )
    lines.append(
        "POSTURE: "
        f"password_encryption={'on' if device.password_encryption else 'off'}, "
        f"source_route={'on' if device.source_route else 'off'}, "
        f"http_server={'on' if device.http_server else 'off'}, "
        f"https_server={'on' if device.https_server else 'off'}, "
        f"ssh_version={device.ssh_version}, "
        f"banner={'present' if device.banner else 'absent'}, "
        f"logging_hosts={device.logging_hosts or 'none'}"
    )
    return "\n".join(lines)


def findings_context(findings: list[Finding]) -> str:
    if not findings:
        return "FINDINGS: none."
    lines = ["FINDINGS (deterministic scanner output):"]
    for f in sorted(findings, key=lambda x: x.severity.value):
        lines.append(f"  - [{f.severity.value}] {f.rule_id}: {f.title}  ({f.evidence})")
    return "\n".join(lines)


# -- config syntax guard ------------------------------------------------------

# First tokens of legal IOS config-mode lines. Anything else is non-config text
# and is rejected.
_KNOWN_VERBS = {
    "interface", "ip", "no", "snmp-server", "line", "access-list", "permit",
    "deny", "service", "hostname", "logging", "banner", "ntp", "username",
    "exit", "end", "configure", "switchport", "cdp", "crypto", "aaa", "route",
    "transport", "login", "password", "access-class", "description", "vlan",
    "shutdown", "clock", "enable", "scheduler", "spanning-tree", "mac-address",
    "arp", "speed", "duplex", "mtu", "bandwidth", "delay",
}


def lint_config_delta(text: str) -> list[tuple[int, str]]:
    """Return (line_no, line) pairs that don't look like valid IOS config.

    Used to validate model-generated config before it is shown.
    """
    issues: list[tuple[int, str]] = []
    for n, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if not s or s.startswith("!"):
            continue
        tok = s.split()[0]
        if tok not in _KNOWN_VERBS:
            issues.append((n, s))
    return issues


def _strip_fences(text: str) -> str:
    """Strip a surrounding ```...``` or ```ios...``` fence if present."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else t[3:]
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


# -- prompts ------------------------------------------------------------------

_QA_SYSTEM = (
    "You are a senior network security engineer reviewing a Cisco IOS device. "
    "Answer the operator's question using ONLY the structured device facts and "
    "findings provided. Be specific and cite the named interface/ACL/community. "
    "If the facts do not cover something, say 'not present in config' rather than "
    "guessing. Keep answers under 120 words."
)

_REMEDIATE_SYSTEM = (
    "You are a Cisco IOS engineer. The operator describes a change in natural "
    "language. Using ONLY the provided device facts, output the minimal set of "
    "valid IOS config-mode commands that implements it. Rules:\n"
    "- Output ONLY config commands. No prose, no explanations, no markdown fences.\n"
    "- Prefer 'no ...' forms to remove existing config.\n"
    "- Do not invent interfaces, ACLs, or addresses not implied by the request or facts.\n"
    "- End with the single word: end"
)

_SUMMARY_SYSTEM = (
    "You are a network security assessor. Given a device's facts and the scanner "
    "findings, write a 3-4 sentence summary: overall posture, the most "
    "urgent risk, and the single highest-value fix. Plain language, no bullets."
)


# -- public operations --------------------------------------------------------

def ask(device: Device, findings: list[Finding], question: str,
        client: LLMClient) -> str:
    user = f"{device_context(device)}\n\n{findings_context(findings)}\n\nQUESTION: {question}"
    return client.complete(_QA_SYSTEM, user, temperature=0.1, max_tokens=400)


def generate_remediation(device: Device, instruction: str,
                         client: LLMClient) -> tuple[str, list[tuple[int, str]]]:
    """Return (config_delta, lint_issues). Lint issues flag non-config prose."""
    user = f"{device_context(device)}\n\nREQUEST: {instruction}"
    raw = client.complete(_REMEDIATE_SYSTEM, user, temperature=0.0, max_tokens=512)
    delta = _strip_fences(raw)
    return delta, lint_config_delta(delta)


def summarize(device: Device, findings: list[Finding],
              client: LLMClient) -> str:
    user = f"{device_context(device)}\n\n{findings_context(findings)}"
    return client.complete(_SUMMARY_SYSTEM, user, temperature=0.2, max_tokens=300)
