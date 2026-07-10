"""Detection rule registry.

Rules are registered per-OS and operate on the normalized :class:`Device`.
Adding a check = write a function, decorate it, done. The scanner runs every
rule whose OS matches the parsed device.
"""
from __future__ import annotations

from typing import Callable, Protocol

from ..finding import Finding
from ..model import Device


class Rule(Protocol):
    __name__: str

    def __call__(self, device: Device) -> list[Finding]: ...


_REGISTRY: dict[str, list[Rule]] = {}


def register(os_name: str) -> Callable[[Rule], Rule]:
    def deco(fn: Rule) -> Rule:
        _REGISTRY.setdefault(os_name, []).append(fn)
        return fn
    return deco


def run(device: Device) -> list[Finding]:
    findings: list[Finding] = []
    for fn in _REGISTRY.get(device.os, []):
        findings.extend(fn(device))
    return findings


def registered(os_name: str) -> list[Rule]:
    return list(_REGISTRY.get(os_name, []))
# importing these modules populates the registry via decorators
from . import ios  # noqa: E402,F401
from . import panos  # noqa: E402,F401
