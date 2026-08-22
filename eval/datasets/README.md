# Eval datasets

Datasets for `eval/run.py` (the v2 harness — distinct from the original
`eval/dataset.jsonl` + `eval/run_eval.py`, which are unchanged and still
work independently).

## Schema

One JSON object per line (`.jsonl`). Every row must have all ten fields.

| Field | Type | Values | Notes |
| --- | --- | --- | --- |
| `id` | string | free-form, unique | e.g. `v1-001` |
| `text` | string | the message body | never includes the sender header |
| `sender` | string | free-form, or `"unknown"` | the sender identity, masked (e.g. `+91 98XXXXXX21`) — never a real number |
| `sender_type` | enum | `dlt_header`, `mobile_10d`, `intl`, `shortcode`, `unknown` | how the sender presents |
| `lang` | string | ISO 639-1 (`en`, `hi`, `te`, ...) | primary language of `text` |
| `label` | enum | `legit`, `scam`, `unclear` | ground truth |
| `category` | enum | `kyc_payment`, `govt_impersonation`, `investment_trading`, `fake_customer_care`, `phishing_link`, `job_lottery`, `digital_arrest`, `txn_alert`, `otp`, `promo` | scam theme, or the closest theme for a legit/unclear row |
| `ask_class` | enum | `none`, `click`, `call_back`, `share_credential`, `make_payment`, `install_app` | the action the message is asking for |
| `hard_negative` | boolean | `true` / `false` | `true` = legit message that looks scam-like (urgency, links, payment mentions) — the case that actually stresses the false-positive rate |
| `source` | string | free-form | provenance, see below |

## Why two scoring passes

`eval/run.py` scores every row twice:

- **`with_sender`** — `sender` is prepended to `text` as a `From: <sender>`
  header line before calling the engine.
- **`sender_stripped`** — `text` alone, with no header at all.

This matters because WhatsApp-forwarded messages — a large share of what
Kavach actually sees in production — usually arrive with no sender header
and no visible number. A dataset scored only "with sender" would overstate
real-world accuracy. Both passes are reported side by side so a gap between
them is visible rather than averaged away.

## Provenance (`source` field)

| Value | Meaning |
| --- | --- |
| `synthetic` | Hand-written for this dataset, modeled on documented scam patterns (MHA/I4C digital arrest advisories, SEBI investor cautions, bank/telecom impersonation reports) and on typical bank/service transactional SMS templates. No real message content. |
| `forwarded` | Hand-written to mimic the *shape* of a WhatsApp-forwarded warning message (second-hand retelling, no original sender info) — not a captured real forward. |

`v1.jsonl` (40 rows) is a hand-authored seed set, not a statistically
representative sample — it exists to exercise every `category` and
`ask_class` value at least once, both `label=legit` variants (including
several `hard_negative=true` rows that mention payment/urgency/links in an
otherwise legitimate context), and every `sender_type`. Treat headline
metrics from it as a smoke test, not a production accuracy claim — grow the
dataset before using it to gate a release.

## Adding rows

Append more `.jsonl` lines to `v1.jsonl`, or add a new `v2.jsonl` etc. and
pass `--dataset eval/datasets/v2.jsonl`. Keep every field populated — `run.py`
skips (with a warning) any row missing a required field.
