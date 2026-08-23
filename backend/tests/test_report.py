"""Tests for services.report — the CHAKSHU_CATEGORY_MAP and its wiring into
build_report()'s "chakshu_category" field.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.report import CHAKSHU_CATEGORY_MAP, build_report
from services.rules import SCAM_TAXONOMY


def test_chakshu_category_map_covers_every_scam_taxonomy_value():
    for scam_type in SCAM_TAXONOMY:
        # KeyError would raise here if a value were missing — .get with a
        # sentinel makes the failure message clearer than a bare KeyError.
        assert scam_type in CHAKSHU_CATEGORY_MAP, f"CHAKSHU_CATEGORY_MAP missing {scam_type!r}"


def test_digital_arrest_chakshu_category():
    verdict = {
        "scam_type": "digital_arrest",
        "risk": 90,
        "signals": ["authority", "fear"],
        "detected_language": "en",
    }
    report = build_report(verdict, "This is CBI, you are under digital arrest.")
    assert report["chakshu_category"] == "Impersonation as Police, CBI, Customs, Aadhaar, RBI etc"


def test_likely_safe_chakshu_category_is_none():
    verdict = {
        "scam_type": "likely_safe",
        "risk": 5,
        "signals": [],
        "detected_language": "en",
    }
    report = build_report(verdict, "Your OTP is 123456. Do not share it with anyone.")
    assert report["chakshu_category"] is None


def test_kyc_bank_chakshu_category():
    verdict = {
        "scam_type": "kyc_bank",
        "risk": 85,
        "signals": ["credential_request"],
        "detected_language": "en",
    }
    report = build_report(verdict, "Your KYC has expired, click here to verify.")
    assert (
        report["chakshu_category"]
        == "KYC and Payment related to Bank / Electricity / Gas / Insurance etc"
    )


def test_job_task_and_lottery_prize_share_chakshu_category():
    for scam_type in ("job_task", "lottery_prize", "loan_app"):
        verdict = {"scam_type": scam_type, "risk": 80, "signals": [], "detected_language": "en"}
        report = build_report(verdict, "test message")
        assert report["chakshu_category"] == "Online job / lottery / gifts / loan offers"
