"""Locale registry: discovers locales/<code>/ directories at import time.

Adding a language is a pure data change — drop a new locales/<code>/
directory containing lexicon.yaml and responses.yaml (matching the keys in
_schema.yaml) and it is picked up automatically. No code changes required.

Public API:
  - LocaleBundle: dataclass holding one locale's parsed data
  - REGISTRY: dict[str, LocaleBundle], populated at import time
  - get_locale(code) -> LocaleBundle | None
  - available_locales() -> list[str]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

_LOCALES_DIR = Path(__file__).resolve().parent
_SCHEMA_PATH = _LOCALES_DIR / "_schema.yaml"


@dataclass(frozen=True)
class LocaleBundle:
    code: str
    lexicon: dict = field(default_factory=dict)
    responses: dict = field(default_factory=dict)


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_schema() -> dict:
    """Load _schema.yaml describing required files/keys for every locale."""
    return _load_yaml(_SCHEMA_PATH)


def _discover_locale_dirs() -> list[Path]:
    """Every subdirectory of locales/ that contains a lexicon.yaml is a locale."""
    if not _LOCALES_DIR.is_dir():
        return []
    dirs = []
    for entry in sorted(_LOCALES_DIR.iterdir()):
        if entry.is_dir() and (entry / "lexicon.yaml").is_file():
            dirs.append(entry)
    return dirs


def _build_registry() -> dict[str, LocaleBundle]:
    registry: dict[str, LocaleBundle] = {}
    for locale_dir in _discover_locale_dirs():
        code = locale_dir.name
        lexicon_path = locale_dir / "lexicon.yaml"
        responses_path = locale_dir / "responses.yaml"

        lexicon = _load_yaml(lexicon_path) if lexicon_path.is_file() else {}
        responses = _load_yaml(responses_path) if responses_path.is_file() else {}

        registry[code] = LocaleBundle(code=code, lexicon=lexicon, responses=responses)
    return registry


REGISTRY: dict[str, LocaleBundle] = _build_registry()


def get_locale(code: str) -> LocaleBundle | None:
    return REGISTRY.get(code)


def available_locales() -> list[str]:
    return sorted(REGISTRY.keys())
