"""Maps eval/datasets/v2.jsonl rows to the engine's SCAM_TAXONOMY (backend/
services/rules.py) so eval/run.py can score v2 against the real engine
categories.

v2's `category` field is a coarse dataset theme, not an alias of
SCAM_TAXONOMY: several categories (`otp`, `promo`, `txn_alert`,
`kyc_payment`, `phishing_link`, `job_lottery`) mix multiple engine-facing
scam types or both legit and scam rows under one theme name. So the mapping
is a function of (category, label, ask_class, text), not a static
category -> type dict. See eval/datasets/PROVENANCE.md for row content this
was built against.

Public API:
  - map_row_to_scam_type(row: dict) -> str  (one of SCAM_TAXONOMY)

Judgment calls (confirmed with the team 2026-08-23):
  - label != "scam" (legit/unclear rows) never map to a scam_type: legit ->
    likely_safe, unclear -> other (the abstain bucket) rather than
    likely_safe, so an unclear-but-actually-risky row doesn't get silently
    absorbed into the "safe" bucket in FPR/recall math.
  - govt_impersonation -> digital_arrest: no separate authority-impersonation
    slot exists in SCAM_TAXONOMY; digital_arrest's fear/authority-coercion
    shape is the closest fit.
  - phishing_link scam rows split by content: courier/customs -> courier_parcel,
    virus/antivirus/device-security -> tech_support, loan pre-approval ->
    loan_app, electricity-bill and Netflix-subscription payment-link phishing
    -> kyc_bank (credential/payment-detail-update phishing, same mechanism as
    KYC scams, even though the cover story differs).
  - job_lottery scam rows split by ask_class + keyword: make_payment tied to
    job/work/task/data-entry language -> job_task; "won"/lucky-draw/giveaway
    language -> lottery_prize.
"""

from __future__ import annotations

import re

# Mirror of backend/services/rules.SCAM_TAXONOMY, duplicated intentionally:
# eval/ must not import from backend/ at module scope beyond what run.py
# already does for analyze(), and this list is asserted against the real
# taxonomy in tests/tooling that import both, so drift is caught.
SCAM_TAXONOMY: list[str] = [
    "digital_arrest",
    "investment_stock",
    "kyc_bank",
    "courier_parcel",
    "job_task",
    "loan_app",
    "lottery_prize",
    "tech_support",
    "upi_collect_request",
    "romance",
    "deepfake_voice",
    "other",
    "likely_safe",
]

_COURIER_RE = re.compile(r"customs|parcel|shipment|courier|redeliver", re.IGNORECASE)
_TECH_SUPPORT_RE = re.compile(r"virus|antivirus|security app|device", re.IGNORECASE)
_LOAN_RE = re.compile(r"loan|pre-approved|processing fee", re.IGNORECASE)
_BILL_PHISH_RE = re.compile(
    r"electricity|disconnect|netflix|subscription|payment method", re.IGNORECASE
)

_LOTTERY_KEYWORD_RE = re.compile(
    r"\bwon\b|lucky draw|giveaway|kbc|iphone", re.IGNORECASE
)


def _map_phishing_link_scam(text: str) -> str:
    """phishing_link/scam rows cover 5 distinct cover stories — see module
    docstring for the confirmed judgment calls per story."""
    if _COURIER_RE.search(text):
        return "courier_parcel"
    if _TECH_SUPPORT_RE.search(text):
        return "tech_support"
    if _LOAN_RE.search(text):
        return "loan_app"
    if _BILL_PHISH_RE.search(text):
        return "kyc_bank"
    return "other"


def _map_job_lottery_scam(ask_class: str, text: str) -> str:
    """job_lottery/scam rows mix fee-for-job scams and lucky-draw/giveaway
    scams under one category name; ask_class + keyword decide which."""
    if _LOTTERY_KEYWORD_RE.search(text):
        return "lottery_prize"
    if ask_class == "make_payment":
        return "job_task"
    return "job_task"


# Categories where every scam row maps to the same single scam_type,
# regardless of content.
_SIMPLE_SCAM_MAP: dict[str, str] = {
    "kyc_payment": "kyc_bank",
    "otp": "kyc_bank",
    "promo": "lottery_prize",
    "txn_alert": "upi_collect_request",
    "digital_arrest": "digital_arrest",
    "govt_impersonation": "digital_arrest",
    "investment_trading": "investment_stock",
    "fake_customer_care": "tech_support",
}

# Categories that need row content (text / ask_class) to resolve which
# scam_type a scam row maps to.
_CONTENT_AWARE_CATEGORIES = {"phishing_link", "job_lottery"}


def map_row_to_scam_type(row: dict) -> str:
    """Return the SCAM_TAXONOMY value a v2.jsonl row maps to.

    `row` must have `category`, `label`, `text`, and `ask_class` (the v2
    schema — see eval/datasets/README.md). Never raises: an unrecognized
    category or malformed row maps to "other" rather than failing the row.
    """
    label = row.get("label")
    category = row.get("category")

    if label == "legit":
        return "likely_safe"
    if label != "scam":
        # "unclear" (and any unexpected label) -> the abstain bucket, not
        # likely_safe, so it isn't counted as a confirmed-safe row.
        return "other"

    if category in _CONTENT_AWARE_CATEGORIES:
        text = row.get("text") or ""
        if category == "phishing_link":
            return _map_phishing_link_scam(text)
        if category == "job_lottery":
            return _map_job_lottery_scam(row.get("ask_class") or "", text)

    return _SIMPLE_SCAM_MAP.get(category, "other")
