"""Normalized network device model.

A vendor parser turns a raw config into a :class:`Device`. Detection rules and
the (future) knowledge-graph / reachability layers all operate on this shape,
so the rest of the system never touches vendor syntax directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Interface:
    name: str
    description: str | None = None
    ip_address: str | None = None          # dotted-quad
    subnet_mask: str | None = None         # dotted-quad mask (IOS style)
    shutdown: bool = True
    vlan: int | None = None
    access_group_in: str | None = None     # ACL name applied inbound
    access_group_out: str | None = None    # ACL name applied outbound
    cdp_enabled: bool | None = None        # None = platform default
    line: int | None = None                # config line number (citation)


@dataclass
class ACLEntry:
    action: str                             # permit | deny
    protocol: str                           # ip | tcp | udp | icmp | ...
    source: str                             # "any" | "host 1.2.3.4" | "10.0.0.0 0.0.0.255"
    dest: str
    dst_port: str | None = None            # "eq 443"
    established: bool = False
    log: bool = False
    raw: str = ""
    line: int | None = None


@dataclass
class ACL:
    name: str
    kind: str = "extended"                  # standard | extended
    applied: list[str] = field(default_factory=list)  # where it's bound
    entries: list[ACLEntry] = field(default_factory=list)
    line: int | None = None


@dataclass
class SNMPCommunity:
    name: str
    access: str = "RO"                      # RO | RW
    version: str = "2c"                     # 1 | 2c (v3 lives elsewhere)
    line: int | None = None


@dataclass
class LineConfig:
    name: str                               # vty | con | aux
    transport_input: list[str] = field(default_factory=list)  # ["telnet","ssh"]
    login: str | None = None               # None | "local" | "aaa" | "" (login) | "none"
    password_present: bool = False
    password_type: int | None = None       # 0=clear 5=MD5 7=Cisco proprietary
    access_class: str | None = None
    line: int | None = None


@dataclass
class Zone:
    name: str
    interfaces: list[str] = field(default_factory=list)
    layer3: bool = True
    line: int | None = None


@dataclass
class SecurityRule:
    """A firewall policy rule (PAN-OS security rule; generalizes to zone-firewalls)."""
    name: str
    from_zones: list[str] = field(default_factory=list)
    to_zones: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    destinations: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    action: str = "allow"            # allow | deny | drop | reset-client | reset-server
    log_end: bool = False
    log_start: bool = False
    line: int | None = None


@dataclass
class Service:
    name: str
    protocol: str                    # tcp | udp
    port: str                        # "443" or "4430-4450"
    line: int | None = None

@dataclass
class Device:
    hostname: str = "unknown"
    vendor: str = "cisco"
    os: str = "ios"
    version: str | None = None

    interfaces: list[Interface] = field(default_factory=list)
    acls: list[ACL] = field(default_factory=list)
    snmp: list[SNMPCommunity] = field(default_factory=list)
    lines: list[LineConfig] = field(default_factory=list)

    # management-plane / crypto posture
    ssh_version: int | None = None          # None = unset; 1 = bad; 2 = good
    http_server: bool = False               # cleartext web UI
    https_server: bool = False
    password_encryption: bool = False       # service password-encryption
    source_route: bool = True               # IOS default ON until "no ip source-route"

    # ops hygiene
    logging_hosts: list[str] = field(default_factory=list)
    ntp_servers: list[str] = field(default_factory=list)
    local_users: list[str] = field(default_factory=list)
    banner: bool = False

    # firewall-policy objects (populated by zone-firewall parsers, e.g. PAN-OS)
    zones: list[Zone] = field(default_factory=list)
    security_rules: list[SecurityRule] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    addresses: dict[str, str] = field(default_factory=dict)  # name -> cidr
    mgmt_ip: str | None = None

    # raw config for citation
    config_lines: list[str] = field(default_factory=list)

    def acl(self, name: str) -> ACL | None:
        return next((a for a in self.acls if a.name == name), None)
