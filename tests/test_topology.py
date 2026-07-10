from pathlib import Path

from sentinel.parsers.ios import parse
from sentinel.topology import (
    Flow,
    _match_addr,
    build_graph,
    evaluate_acl,
    reachability,
)

FIX = Path(__file__).parent / "fixtures"


def _graph():
    files = ["topo_edge.cfg", "topo_core.cfg"]
    devices = [parse((FIX / f).read_text()) for f in files]
    return build_graph(devices)


# -- ACL matching primitives --------------------------------------------------

def test_match_any_and_host():
    assert _match_addr("any", "8.8.8.8")
    assert _match_addr("host 1.2.3.4", "1.2.3.4")
    assert not _match_addr("host 1.2.3.4", "1.2.3.5")


def test_match_wildcard():
    assert _match_addr("10.0.0.0 0.0.0.255", "10.0.0.50")
    assert not _match_addr("10.0.0.0 0.0.0.255", "10.0.1.50")


def test_implicit_deny():
    from sentinel.model import ACL
    acl = ACL(name="X", kind="extended",
              entries=[])  # no permit => implicit deny
    action, entry = evaluate_acl(acl, Flow("10.0.0.1", "10.0.0.2", "tcp", 80))
    assert action == "deny" and entry is None


# -- graph construction -------------------------------------------------------

def test_infers_adjacency_via_shared_subnet():
    g = _graph()
    assert g.adj["edge-rtr"] == {"core-rtr"}
    assert g.adj["core-rtr"] == {"edge-rtr"}
    # the transit link shows both devices on one segment
    transit = next(s for s in g.segments if s.network == "10.0.0.0/30")
    assert {h for h, _ in transit.members} == {"edge-rtr", "core-rtr"}


# -- reachability: permit + deny with citation --------------------------------

def test_lan_a_to_lan_b_443_permitted():
    g = _graph()
    r = reachability(g, Flow("10.0.1.50", "10.0.2.50", "tcp", 443))
    assert r.reachable
    assert r.path[0].device == "core-rtr"
    assert r.path[0].acl == "LAN-RESTRICT"
    assert "443" in r.rule


def test_lan_a_to_lan_b_22_denied_by_acl():
    g = _graph()
    r = reachability(g, Flow("10.0.1.50", "10.0.2.50", "tcp", 22))
    assert not r.reachable
    assert r.acl_name == "LAN-RESTRICT"
    assert "deny ip any any" in r.rule


def test_internet_to_lan_blocked_at_edge():
    g = _graph()
    r = reachability(g, Flow("203.0.113.50", "10.0.1.50", "tcp", 443))
    assert not r.reachable
    assert r.path[0].device == "edge-rtr"
    assert r.acl_name == "INET-IN"


def test_internet_to_edge_mgmt_permitted():
    g = _graph()
    r = reachability(g, Flow("203.0.113.50", "203.0.113.2", "tcp", 22))
    assert r.reachable
    assert r.acl_name is None or r.rule and "22" in r.rule


def test_unknown_endpoint_explained():
    g = _graph()
    r = reachability(g, Flow("172.16.99.99", "10.0.1.50", "tcp", 80))
    assert not r.reachable
    assert "not on any known segment" in r.detail
