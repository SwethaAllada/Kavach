"""Rule-pack registry for backend/engine.

A "rule pack" is a named, versionable bundle of deterministic scam-detection
rules. This module is a stub registry: rule packs register themselves here
so the fusion layer can look them up by name without importing every pack
directly.

Must not import backend.core (see backend/engine/__init__.py).
"""

from __future__ import annotations

RULE_PACKS: dict[str, object] = {}


def register(name: str, pack: object) -> None:
    """Register a rule pack under `name`, overwriting any existing entry."""
    RULE_PACKS[name] = pack


def get(name: str) -> object | None:
    return RULE_PACKS.get(name)


def available() -> list[str]:
    return sorted(RULE_PACKS.keys())
