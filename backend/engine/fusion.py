"""Fusion layer stub: combines rule-pack signals, LLM reasoning, and lexical
RAG hits into a single verdict.

Not wired into the request path yet — backend/core's existing pipeline is
untouched. This is scaffolding for a future additive integration.

Must not import backend.core (see backend/engine/__init__.py).
"""

from __future__ import annotations


def fuse(*, rule_signals: list | None = None, llm_output: dict | None = None,
          rag_hits: list | None = None) -> dict:
    """Combine signals from rules, LLM, and RAG into a single verdict dict.

    Stub implementation: returns an empty/unclear verdict shape. Real fusion
    logic lands in a future change.
    """
    return {
        "verdict": "unclear",
        "rule_signals": rule_signals or [],
        "llm_output": llm_output or {},
        "rag_hits": rag_hits or [],
    }
