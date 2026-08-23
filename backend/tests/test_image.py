"""Tests for POST /analyze-image.

All tests mock services.vision.extract_text_from_image AND the LLM call, so
they run fully offline — no real vision API call, no real xAI credential
needed. The engine (classifier + rules + RAG + report) runs for real on
whatever text the mocked vision call "extracted".
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from core.config import settings
from main import app
from routes import image as image_route
from services import classifier as classifier_module
from services import llm as llm_module
from services.llm import LLMUnavailable
from services.vision import VisionExtractionFailed, VisionUnavailable

client = TestClient(app)


@pytest.fixture(autouse=True)
def _disable_rate_limit(monkeypatch):
    # /analyze-image is rate-limited like /analyze and /webhook (same shared,
    # process-wide, per-IP sliding-window limiter in main.py). This suite
    # isn't testing rate-limit behavior (see test_security.py for that), and
    # every TestClient request in the whole pytest session shares one IP, so
    # leaving the limiter on here would make this file's pass/fail depend on
    # how many requests OTHER test files already sent in the same run.
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    yield

# A tiny valid PNG (1x1 transparent pixel) — real image bytes, not required
# to contain any legible text since the vision call itself is mocked.
_TINY_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000a49444154789c6360000002000100ffff03000006000557bfabd4000000"
    "0049454e44ae426082"
)


@pytest.fixture(autouse=True)
def _force_llm_unavailable(monkeypatch):
    """Same discipline as test_analyze.py: force the text-classification
    LLM off so these tests run without a live xAI credential. Individual
    tests override with their own monkeypatch when they want a specific
    fused verdict."""

    def _raise(_text: str, grounding: str = ""):
        raise LLMUnavailable("mocked: llm disabled in tests")

    monkeypatch.setattr(llm_module, "analyze_message", _raise)
    monkeypatch.setattr(classifier_module.llm_service, "analyze_message", _raise)
    yield


def _mock_vision_success(text: str, sender: str | None = None):
    def _fake(_image_bytes: bytes, _mime_type: str) -> dict:
        return {"text": text, "sender": sender}

    return _fake


# ---------------------------------------------------------------------------
# Content-type validation
# ---------------------------------------------------------------------------


def test_non_image_content_type_returns_422():
    r = client.post(
        "/analyze-image",
        files={"image": ("message.txt", io.BytesIO(b"not an image"), "text/plain")},
    )
    assert r.status_code == 422


def test_gif_content_type_rejected():
    r = client.post(
        "/analyze-image",
        files={"image": ("message.gif", io.BytesIO(b"GIF89a"), "image/gif")},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Size limit
# ---------------------------------------------------------------------------


def test_oversized_image_returns_413():
    oversized = b"\x00" * (5 * 1024 * 1024 + 1)
    r = client.post(
        "/analyze-image",
        files={"image": ("big.png", io.BytesIO(oversized), "image/png")},
    )
    assert r.status_code == 413


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_valid_image_returns_verdict_with_extracted_fields(monkeypatch):
    monkeypatch.setattr(
        image_route,
        "extract_text_from_image",
        _mock_vision_success(
            "Your KYC has expired, click here to verify: http://fake-bank.link",
            sender="VM-HDFCBK",
        ),
    )

    r = client.post(
        "/analyze-image",
        files={"image": ("screenshot.png", io.BytesIO(_TINY_PNG), "image/png")},
    )
    assert r.status_code == 200
    body = r.json()

    # Same Verdict shape as /analyze...
    for field in (
        "scam_type", "risk", "confidence", "decision_source", "fallback_used",
        "signals", "matched_patterns", "artifacts", "explanation",
        "recommended_action", "report", "detected_language",
    ):
        assert field in body, f"missing field: {field}"

    # ...plus the two extraction fields.
    assert body["extracted_text"] == "Your KYC has expired, click here to verify: http://fake-bank.link"
    assert body["extracted_sender"] == "VM-HDFCBK"


def test_extracted_sender_null_when_not_found(monkeypatch):
    monkeypatch.setattr(
        image_route,
        "extract_text_from_image",
        _mock_vision_success("Some message with no visible sender", sender=None),
    )

    r = client.post(
        "/analyze-image",
        files={"image": ("screenshot.jpg", io.BytesIO(_TINY_PNG), "image/jpeg")},
    )
    assert r.status_code == 200
    assert r.json()["extracted_sender"] is None


# ---------------------------------------------------------------------------
# Vision failure paths
# ---------------------------------------------------------------------------


def test_vision_extraction_failed_returns_422(monkeypatch):
    def _fake(_image_bytes: bytes, _mime_type: str) -> dict:
        raise VisionExtractionFailed("no text found in image")

    monkeypatch.setattr(image_route, "extract_text_from_image", _fake)

    r = client.post(
        "/analyze-image",
        files={"image": ("blank.png", io.BytesIO(_TINY_PNG), "image/png")},
    )
    assert r.status_code == 422
    assert "paste the message text" in r.json()["detail"].lower()


def test_vision_unavailable_returns_503(monkeypatch):
    def _fake(_image_bytes: bytes, _mime_type: str) -> dict:
        raise VisionUnavailable("mocked: vision model unreachable")

    monkeypatch.setattr(image_route, "extract_text_from_image", _fake)

    r = client.post(
        "/analyze-image",
        files={"image": ("screenshot.png", io.BytesIO(_TINY_PNG), "image/png")},
    )
    assert r.status_code == 503
    assert "temporarily unavailable" in r.json()["detail"].lower()
    assert "paste the message text" in r.json()["detail"].lower()
