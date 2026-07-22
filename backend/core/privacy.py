"""Privacy layer for anonymized telemetry.

`to_anonymized_record(verdict)` accepts a fully-formed Verdict dict and returns
ONLY the whitelisted anonymized fields. Everything else — message text,
prefilled_summary, matched_indicators (which echo user phrasing), phones/UPI/
URLs — is dropped.

The whitelist is hard-coded and defensively enforced: even if the caller passes
a Verdict with extra top-level keys, this function refuses to include them.
"""

from __future__ import annotations

from typing import Any

# The COMPLETE, non-negotiable whitelist of what we're allowed to persist.
# Load-bearing for the pitch — reviewers should be able to open this file
# and see the entire set in one place.
_WHITELISTED_KEYS: frozenset[str] = frozenset(
    {
        "scam_type",
        "risk_bucket",
        "detected_language",
        "decision_source",
        "fallback_used",
    }
)


def _bucket_risk(risk: Any) -> str:
    """Map raw risk score to a coarse bucket. Anything invalid -> 'low'."""
    try:
        r = int(risk)
    except (TypeError, ValueError):
        return "low"
    if r >= 70:
        return "high"
    if r >= 40:
        return "medium"
    return "low"


def _coerce_str(value: Any, fallback: str) -> str:
    if isinstance(value, str) and value:
        return value
    return fallback


def to_anonymized_record(verdict: dict) -> dict:
    """Return the whitelist projection of `verdict`. Never raises.

    Guarantees:
      - The returned dict contains ONLY keys in `_WHITELISTED_KEYS`.
      - No user-supplied string (message text, phones, UPI IDs, URLs,
        indicator phrases, prefilled_summary) is present anywhere in the
        returned dict, because those keys are not read at all.
      - `risk_bucket` is derived and stored instead of the raw risk score,
        so exact risk values are not persisted either.
    """
    if not isinstance(verdict, dict):
        verdict = {}

    record = {
        "scam_type": _coerce_str(verdict.get("scam_type"), "other"),
        "risk_bucket": _bucket_risk(verdict.get("risk")),
        "detected_language": _coerce_str(verdict.get("detected_language"), "en"),
        "decision_source": _coerce_str(verdict.get("decision_source"), "unknown"),
        "fallback_used": bool(verdict.get("fallback_used", False)),
    }

    # Defensive guard: fail closed if we ever accidentally introduce an
    # unwhitelisted key upstream. This is a code-integrity assertion, not a
    # runtime check on user input.
    extra = set(record.keys()) - _WHITELISTED_KEYS
    if extra:  # pragma: no cover — hit only if _WHITELISTED_KEYS drifts
        for k in extra:
            record.pop(k, None)

    return record


def anonymized_fields() -> frozenset[str]:
    """Expose the whitelist for tests, docs, and code review."""
    return _WHITELISTED_KEYS
