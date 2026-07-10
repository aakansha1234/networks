"""Multi-device network graph + ACL-aware reachability.

Given several parsed devices, infer L3 adjacencies (two devices are adjacent when
they each hold an interface in the same subnet), build a network-wide graph, and
answer end-to-end questions like "can host A reach host B on TCP/443?" — evaluating
the Cisco ACL semantics (wildcard matching, first-match, implicit deny) at every
ingress interface along the path, with a citation to the exact rule that decided
the flow.

The answer is computed, not guessed; every decision points at a config line.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .model import ACL, ACLEntry, Device

_PROTOS = {"tcp", "udp", "ip", "icmp", "gre", "esp"}


# -- flow + result models -----------------------------------------------------

@dataclass
class Flow:
    src: str            # source IP
    dst: str            # destination IP
    proto: str          # tcp | udp | ip | icmp | ...
    port: int | None = None


@dataclass
class Hop:
    device: str
    interface: str
    acl: str | None     # inbound ACL name applied on this interface, if any


@dataclass
class ReachResult:
    reachable: bool
    path: list[Hop] = field(default_factory=list)
    detail: str = ""
    acl_name: str | None = None
    rule: str | None = None       # the deciding entry's raw line, or "implicit deny"
    line: int | None = None


# -- ACL evaluation -----------------------------------------------------------

def _ip_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def _match_addr(spec: str, ip: str) -> bool:
    """Match a parsed ACL address spec against a concrete IP."""
    if spec == "any":
        return True
    parts = spec.split()
    if len(parts) == 2 and parts[0] == "host":
        return ip == parts[1]
    if len(parts) == 2:  # "net wildcard"  (Cisco wildcard mask)
        net, wild = parts
        try:
            net_i, wild_i = _ip_int(net), _ip_int(wild)
        except ValueError:
            return False
        mask = (~wild_i) & 0xFFFFFFFF
        return (_ip_int(ip) & mask) == (net_i & mask)
    try:                  # bare IP literal
        return ip == spec
    except ValueError:
        return False


def _proto_match(entry_proto: str, flow_proto: str) -> bool:
    return entry_proto == "ip" or entry_proto == flow_proto


def _port_match(port_spec: str, port: int) -> bool:
    op, _, val = port_spec.partition(" ")
    if op == "eq":
        return str(port) == val
    if op == "gt":
        return port > int(val)
    if op == "lt":
        return port < int(val)
    return False


def evaluate_acl(acl: ACL, flow: Flow) -> tuple[str, ACLEntry | None]:
    """First-match-wins; returns (action, entry). No match => implicit deny."""
    for e in acl.entries:
        if not _proto_match(e.protocol, flow.proto):
            continue
        if not _match_addr(e.source, flow.src):
            continue
        if not _match_addr(e.dest, flow.dst):
            continue
        if e.dst_port:
            if flow.port is None or not _port_match(e.dst_port, flow.port):
                continue
        return (e.action, e)
    return ("deny", None)


# -- network graph ------------------------------------------------------------

@dataclass
class Segment:
    network: str                         # "10.0.0.0/30"
    members: list[tuple[str, str]]       # (hostname, interface_name)


@dataclass
class NetworkGraph:
    devices: dict[str, Device]
    segments: list[Segment]
    adj: dict[str, set[str]]


def _net_of(ip: str, mask: str) -> str | None:
    try:
        return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
    except ValueError:
        return None


def build_graph(devices: list[Device]) -> NetworkGraph:
    seg_map: dict[str, list[tuple[str, str]]] = {}
    for dev in devices:
        for iface in dev.interfaces:
            if not iface.ip_address or not iface.subnet_mask:
                continue
            net = _net_of(iface.ip_address, iface.subnet_mask)
            if net:
                seg_map.setdefault(net, []).append((dev.hostname, iface.name))
    segments = [Segment(network=n, members=m) for n, m in seg_map.items()]
    adj: dict[str, set[str]] = {d.hostname: set() for d in devices}
    for seg in segments:
        hosts = [h for h, _ in seg.members]
        for a in hosts:
            for b in hosts:
                if a != b:
                    adj[a].add(b)
    return NetworkGraph(devices={d.hostname: d for d in devices},
                        segments=segments, adj=adj)


def _segment_for_ip(graph: NetworkGraph, ip: str) -> Segment | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for seg in graph.segments:
        if addr in ipaddress.ip_network(seg.network):
            return seg
    return None


def _iface_on_segment(dev: Device, network: str):
    for iface in dev.interfaces:
        if iface.ip_address and _net_of(iface.ip_address, iface.subnet_mask) == network:
            return iface
    return None


def _shared_segment(a: Device, b: Device) -> str | None:
    b_nets = {_net_of(i.ip_address, i.subnet_mask) for i in b.interfaces
              if i.ip_address}
    for i in a.interfaces:
        if not i.ip_address:
            continue
        n = _net_of(i.ip_address, i.subnet_mask)
        if n in b_nets:
            return n
    return None


# -- reachability -------------------------------------------------------------

def _all_simple_paths(graph: NetworkGraph, start: str, goal: str,
                      cap: int = 8) -> list[list[str]]:
    results: list[list[str]] = []

    def dfs(node: str, path: list[str], visited: set[str]) -> None:
        if len(results) >= cap:
            return
        if node == goal:
            results.append(list(path))
            return
        for nb in sorted(graph.adj.get(node, set())):
            if nb in visited:
                continue
            visited.add(nb)
            path.append(nb)
            dfs(nb, path, visited)
            path.pop()
            visited.remove(nb)

    dfs(start, [start], {start})
    return results


def _eval_path(graph: NetworkGraph, path: list[str], flow: Flow,
               src_net: str) -> ReachResult:
    hops: list[Hop] = []
    permit_acl: str | None = None
    permit_rule: str | None = None
    permit_line: int | None = None
    for i, hostname in enumerate(path):
        dev = graph.devices[hostname]
        if i == 0:
            seg_net = src_net
        else:
            prev = graph.devices[path[i - 1]]
            seg_net = _shared_segment(prev, dev) or src_net
        iface = _iface_on_segment(dev, seg_net)
        if iface is None:
            continue
        acl_name = iface.access_group_in
        hops.append(Hop(device=hostname, interface=iface.name, acl=acl_name))
        acl = dev.acl(acl_name) if acl_name else None
        if acl is None:
            continue
        action, entry = evaluate_acl(acl, flow)
        if action != "permit":
            rule = entry.raw if entry else "implicit deny"
            return ReachResult(
                reachable=False, path=hops,
                detail=(f"DENIED at {hostname} {iface.name} by ACL '{acl_name}'"
                        f" — {rule}"),
                acl_name=acl_name, rule=rule,
                line=(entry.line if entry else None),
            )
        # permitted at this hop — remember the deciding rule (last one wins)
        permit_acl = acl_name
        permit_rule = entry.raw if entry else "explicit permit"
        permit_line = entry.line if entry else None
    return ReachResult(
        reachable=True, path=hops,
        detail=(f"PERMITTED along path {' -> '.join(path)}"
                + (f" — last allowed by '{permit_rule}'" if permit_rule else "")),
        acl_name=permit_acl, rule=permit_rule, line=permit_line,
    )


def reachability(graph: NetworkGraph, flow: Flow) -> ReachResult:
    src_seg = _segment_for_ip(graph, flow.src)
    dst_seg = _segment_for_ip(graph, flow.dst)
    if src_seg is None:
        return ReachResult(False, detail=f"source {flow.src} is not on any known segment")
    if dst_seg is None:
        return ReachResult(False, detail=f"destination {flow.dst} is not on any known segment")

    src_devs = {h for h, _ in src_seg.members}
    dst_devs = {h for h, _ in dst_seg.members}
    last_block: ReachResult | None = None
    for s in sorted(src_devs):
        for d in sorted(dst_devs):
            for path in _all_simple_paths(graph, s, d):
                res = _eval_path(graph, path, flow, src_seg.network)
                if res.reachable:
                    return res
                last_block = res
    if last_block is not None:
        return last_block
    return ReachResult(False, detail="no L3 path between source and destination segments")
