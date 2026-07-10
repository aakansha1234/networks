"""Cisco IOS detection rules.

Each rule inspects the normalized :class:`Device` and emits :class:`Finding`
objects citing specific config evidence. Mappings to the CIS Cisco IOS
Benchmark are noted where they apply.
"""
from __future__ import annotations

from ..finding import Finding, Severity
from ..model import Device
from . import register

WELL_KNOWN_COMMUNITIES = {"public", "private", "cisco", "read", "write"}


# -- SNMP ---------------------------------------------------------------------

@register("ios")
def snmp_default_community(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for c in device.snmp:
        if c.name.lower() in WELL_KNOWN_COMMUNITIES:
            out.append(Finding(
                rule_id="IOS-SNMP-001",
                title=f"SNMP community '{c.name}' is a well-known default string",
                severity=Severity.CRITICAL if c.access == "RW" else Severity.HIGH,
                category="snmp",
                description=(
                    f"Default community strings are the first thing scanners brute-force. "
                    f"A read-{'write' if c.access == 'RW' else 'only'} community lets an "
                    f"attacker {'reconfigure' if c.access == 'RW' else 'enumerate'} the device."
                ),
                evidence=f"snmp-server community {c.name} {c.access}",
                line=c.line,
                remediation=(
                    f"no snmp-server community {c.name}\n"
                    "! Move to authenticated/encrypted SNMPv3:\n"
                    "!   snmp-server group ADMINS v3 priv read VIEW write VIEW\n"
                    "!   snmp-server user secadm ADMINS v3 auth sha <auth> priv aes 128 <priv>"
                ),
                cis_ref="CIS 2.1.1",
            ))
    return out


@register("ios")
def snmp_v2c_in_use(device: Device) -> list[Finding]:
    if not device.snmp:
        return []
    # any community string = SNMPv1/v2c (community model, no crypto)
    return [Finding(
        rule_id="IOS-SNMP-002",
        title="SNMPv1/v2c (community-based) is in use instead of SNMPv3",
        severity=Severity.MEDIUM,
        category="snmp",
        description=(
            "Community strings travel the wire in cleartext and offer no per-user "
            "auth or encryption. SNMPv3 (authPriv) is the only version that protects "
            "both integrity and confidentiality."
        ),
        evidence=f"{len(device.snmp)} community string(s): "
                 + ", ".join(c.name for c in device.snmp),
        remediation="! Replace communities with SNMPv3 authPriv groups/users (see IOS-SNMP-001).",
        cis_ref="CIS 2.1.x",
    )]


# -- Access / management plane ------------------------------------------------

@register("ios")
def telnet_enabled(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for lc in device.lines:
        if "telnet" in lc.transport_input and lc.name == "vty":
            has_ssh = "ssh" in lc.transport_input
            out.append(Finding(
                rule_id="IOS-ACCESS-001",
                title="Telnet is permitted on the VTY lines",
                severity=Severity.HIGH if has_ssh else Severity.CRITICAL,
                category="access",
                description=(
                    "Telnet sends credentials in cleartext. If SSH is also enabled this "
                    "is an unnecessary exposure; if it is the only transport the device "
                    "credentials can be sniffed off the wire."
                ),
                evidence=f"transport input {' '.join(lc.transport_input)}",
                line=lc.line,
                remediation="line vty 0 4\n transport input ssh",
                cis_ref="CIS 1.4.1",
            ))
    return out


@register("ios")
def no_login_on_line(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for lc in device.lines:
        if lc.name == "vty" and lc.login == "none":
            out.append(Finding(
                rule_id="IOS-ACCESS-002",
                title="VTY lines have 'no login' — unauthenticated access",
                severity=Severity.CRITICAL,
                category="access",
                description="'no login' skips authentication entirely. Anyone reaching "
                           "the VTY gets a CLI prompt.",
                evidence="no login",
                line=lc.line,
                remediation="line vty 0 4\n login local   ! or: login authentication default (AAA)",
                cis_ref="CIS 1.3.1",
            ))
    return out


@register("ios")
def vty_unrestricted(device: Device) -> list[Finding]:
    out: list[Finding] = []
    has_vty = any(lc.name == "vty" for lc in device.lines)
    if not has_vty:
        return out
    for lc in device.lines:
        if lc.name == "vty" and not lc.access_class:
            out.append(Finding(
                rule_id="IOS-ACCESS-003",
                title="VTY lines accept connections from anywhere (no access-class)",
                severity=Severity.MEDIUM,
                category="access",
                description="Without an inbound ACL the management plane is reachable "
                           "from every subnet that can route to the device.",
                evidence="(no access-class applied under line vty)",
                line=lc.line,
                remediation=(
                    "ip access-list standard MGMT\n permit 10.0.0.0 0.0.0.255\n"
                    "line vty 0 4\n access-class MGMT in"
                ),
                cis_ref="CIS 1.1.2",
            ))
            break
    return out


@register("ios")
def weak_line_password(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for lc in device.lines:
        if lc.name == "vty" and lc.password_present and lc.password_type in (0, 7):
            strength = "cleartext" if lc.password_type == 0 else "weakly-obfuscated (type 7)"
            out.append(Finding(
                rule_id="IOS-ACCESS-004",
                title=f"VTY line password is {strength}",
                severity=Severity.HIGH if lc.password_type == 0 else Severity.MEDIUM,
                category="crypto",
                description=(
                    "Type-0 passwords are stored in cleartext; type-7 is a reversible "
                    "Caesar-style cipher trivially decoded with public tools. Neither "
                    "survives a config leak."
                ),
                evidence=f"password {lc.password_type} <redacted>",
                line=lc.line,
                remediation=(
                    "line vty 0 4\n no password\n login local   ! prefer local user w/ secret"
                ),
                cis_ref="CIS 1.5.1",
            ))
    return out


@register("ios")
def http_server_enabled(device: Device) -> list[Finding]:
    if device.http_server:
        return [Finding(
            rule_id="IOS-MGMT-001",
            title="Cleartext HTTP management server is enabled (ip http server)",
            severity=Severity.MEDIUM,
            category="mgmt",
            description="The HTTP server exposes the web UI without TLS. Credentials "
                       "and session data are sniffable.",
            evidence="ip http server",
            remediation="no ip http server\n! keep: ip http secure-server",
            cis_ref="CIS 2.x",
        )]
    return []


@register("ios")
def password_encryption_off(device: Device) -> list[Finding]:
    if not device.password_encryption:
        return [Finding(
            rule_id="IOS-CRYPTO-001",
            title="'service password-encryption' is not enabled",
            severity=Severity.MEDIUM,
            category="crypto",
            description="Without it, line/console passwords and other type-0 secrets "
                       "are stored in cleartext in the running config.",
            evidence="(service password-encryption absent)",
            remediation="service password-encryption",
            cis_ref="CIS 1.5.1",
        )]
    return []


@register("ios")
def ssh_version_1(device: Device) -> list[Finding]:
    if device.ssh_version == 1:
        return [Finding(
            rule_id="IOS-CRYPTO-002",
            title="SSH protocol version 1 is configured",
            severity=Severity.HIGH,
            category="crypto",
            description="SSHv1 has well-known cryptographic flaws (insertion attacks, "
                       "weak MACs) and is deprecated. Use SSHv2 only.",
            evidence="ip ssh version 1",
            remediation="ip ssh version 2",
            cis_ref="CIS 1.4.x",
        )]
    return []


@register("ios")
def no_ssh_keys(device: Device) -> list[Finding]:
    # If SSH transport is offered but no version is pinned, host may default to v1-capable.
    offers_ssh = any("ssh" in lc.transport_input for lc in device.lines)
    if offers_ssh and device.ssh_version is None:
        return [Finding(
            rule_id="IOS-CRYPTO-003",
            title="SSH transport offered but version is not pinned to 2",
            severity=Severity.MEDIUM,
            category="crypto",
            description="Without 'ip ssh version 2' the device may negotiate the "
                       "deprecated SSHv1 with old clients.",
            evidence="(transport input ssh present, ip ssh version 2 absent)",
            remediation="ip ssh version 2",
        )]
    return []


# -- ACLs ---------------------------------------------------------------------

@register("ios")
def acl_over_permissive(device: Device) -> list[Finding]:
    out: list[Finding] = []
    for acl in device.acls:
        if acl.kind != "extended":
            continue
        for e in acl.entries:
            if e.action != "permit":
                continue
            if e.source == "any" and e.dest == "any":
                # permit ip any any is catastrophic; permit tcp any any (no port) still wide
                sev = Severity.HIGH if e.protocol in ("ip", "tcp", "udp") else Severity.MEDIUM
                out.append(Finding(
                    rule_id="IOS-ACL-001",
                    title=f"ACL '{acl.name}' permits {e.protocol.upper()} from ANY to ANY",
                    severity=sev,
                    category="acl",
                    description=(
                        "A broad 'any any' permit defeats the purpose of the ACL. "
                        "Even as an explicit catch-all it should be a 'deny ... log' so "
                        "rejected traffic is auditable."
                    ),
                    evidence=e.raw,
                    line=e.line,
                    remediation=(
                        f"ip access-list extended {acl.name}\n"
                        f" no {e.raw}\n"
                        "! bound to least privilege: permit <proto> <src> <dst> eq <port>"
                    ),
                ))
    return out


@register("ios")
def source_route_enabled(device: Device) -> list[Finding]:
    if device.source_route:
        return [Finding(
            rule_id="IOS-ROUTE-001",
            title="IP source routing is enabled (default on)",
            severity=Severity.MEDIUM,
            category="route",
            description="Source routing lets a sender dictate the path a packet takes, "
                       "enabling spoofing and bypass of security controls. Disable it.",
            evidence="(no 'no ip source-route' present — IOS default is enabled)",
            remediation="no ip source-route",
            cis_ref="CIS 3.x",
        )]
    return []


@register("ios")
def no_logging_host(device: Device) -> list[Finding]:
    if not device.logging_hosts:
        return [Finding(
            rule_id="IOS-MGMT-002",
            title="No remote syslog destination configured",
            severity=Severity.LOW,
            category="mgmt",
            description="Without remote logging, security-relevant events are lost on "
                       "reboot or disk wipe. Forward to a SIEM/syslog collector.",
            evidence="(logging host absent)",
            remediation="logging host 10.0.0.50\nlogging trap informational",
        )]
    return []


@register("ios")
def no_banner(device: Device) -> list[Finding]:
    if not device.banner:
        return [Finding(
            rule_id="IOS-MGMT-003",
            title="No login banner configured",
            severity=Severity.LOW,
            category="mgmt",
            description="A legal warning banner strengthens the position for prosecution "
                       "and is required by many compliance regimes.",
            evidence="(banner absent)",
            remediation='banner login ^C\nAuthorized access only. Activity is monitored.\n^C',
            cis_ref="CIS 1.x",
        )]
    return []
