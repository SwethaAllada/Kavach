"""Kavach engine: hybrid detection pipeline (rules + LLM reasoning + lexical RAG).

This package is additive scaffolding for the locale-aware rule-pack system.
It must never import from backend.core — core/ may import engine/, but not
the reverse, so the existing request path keeps working untouched while this
package is built out independently.
"""
