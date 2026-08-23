"""Validates every locales/<code>/ directory against locales/_schema.yaml.

This is what makes "adding a language is a data change" actually true: if a
new locale directory is missing a required file or key, this test fails
without anyone touching a line of code.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import pytest

from locales.registry import REGISTRY, load_schema


def test_at_least_one_locale_registered():
    assert REGISTRY, "expected at least one locale under locales/"


def test_schema_loads():
    schema = load_schema()
    assert "files" in schema
    assert "lexicon.yaml" in schema["files"]
    assert "responses.yaml" in schema["files"]


@pytest.mark.parametrize("code", sorted(REGISTRY.keys()))
def test_locale_matches_schema(code):
    schema = load_schema()
    bundle = REGISTRY[code]

    lexicon_required = schema["files"]["lexicon.yaml"]["required_keys"]
    for key in lexicon_required:
        assert key in bundle.lexicon, (
            f"locales/{code}/lexicon.yaml is missing required key '{key}'"
        )

    responses_required = schema["files"]["responses.yaml"]["required_keys"]
    for key in responses_required:
        assert key in bundle.responses, (
            f"locales/{code}/responses.yaml is missing required key '{key}'"
        )

    assert bundle.lexicon.get("language") == code, (
        f"locales/{code}/lexicon.yaml 'language' must equal the directory name"
    )
    assert bundle.responses.get("language") == code, (
        f"locales/{code}/responses.yaml 'language' must equal the directory name"
    )


@pytest.mark.parametrize("code", sorted(REGISTRY.keys()))
def test_locale_required_verdict_keys(code):
    """`verdicts` is optional per _schema.yaml (legacy 5-bucket model with no
    live consumer — see the schema's comment). A locale that omits it
    entirely is valid; a locale that INCLUDES it must have all 5 keys."""
    bundle = REGISTRY[code]
    verdicts = bundle.responses.get("verdicts")
    if verdicts is None:
        pytest.skip(f"locales/{code} has no verdicts block (optional per schema)")
    required_verdicts = ["scam", "likely_scam", "unclear", "likely_legit", "legit"]
    for key in required_verdicts:
        assert key in verdicts, (
            f"locales/{code}/responses.yaml verdicts is missing required key '{key}'"
        )
