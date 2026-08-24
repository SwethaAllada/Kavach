# Eval datasets

Datasets for `eval/run.py` (the v2 harness — distinct from the original
`eval/dataset.jsonl` + `eval/run_eval.py`, which are unchanged and still
work independently).

## Schema

One JSON object per line (`.jsonl`). Every row must have all eleven fields.

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
| `synthetic` | boolean | `true` / `false` | `true` = generated/hand-authored text. `false` = a real message (verbatim extract or `real_phone`). **This is the field that gates what can be quoted externally** — see "synthetic vs. real" below. |

### `synthetic` vs. real — what can go in the deck

`eval/run.py` reports every metric split three ways: **all**, **synthetic
only**, and **real only**.

- **synthetic** metrics are a **regression baseline** — did a rule change
  break something that used to work. Useful for CI/iteration, not for
  external claims, because the text was written to hit specific patterns.
- **real** metrics (from `synthetic: false` rows — verbatim extracts and
  `real_phone` submissions) are the only numbers that can go in a deck,
  README, or pitch. They're currently a small validation subset (5 rows in
  `v2.jsonl` until `real_phone` rows are added), so treat them as a sanity
  check on generalization, not a headline number, until that subset grows.

Never report the "all" or "synthetic" number as if it were a real-world
accuracy claim — `eval/run.py` labels each block explicitly so this can't
happen by accident.

## Why two scoring passes

`eval/run.py` scores every row twice:

- **`with_sender`** — `sender` is passed to `analyze()` as its own structured
  `sender` kwarg, alongside `text`. It is never concatenated into `text`: the
  engine has no sender parser yet, so gluing a header into the message body
  would just be read as message content, not as sender context — that would
  confound this comparison rather than measure it.
- **`sender_stripped`** — `sender=None`, `text` alone, with no header at all.

This matters because WhatsApp-forwarded messages — a large share of what
Kavach actually sees in production — usually arrive with no sender header
and no visible number. A dataset scored only "with sender" would overstate
real-world accuracy. Both passes are reported side by side so a gap between
them is visible rather than averaged away.

## `baseline.json` vs `smoke.json`

`--baseline` normally writes `eval/results/baseline.json`. That name is
reserved for a run over a real, adequately sized dataset. `run.py` checks
the row count and per-label class balance before writing: if the dataset has
fewer than 200 rows, or any of `legit`/`scam`/`unclear` is under 15% of the
set, it prints a loud warning and writes `smoke.json` instead — even if
`--baseline` was passed — so a small run never gets filed under the name
people will trust as the real number. Use `--force-baseline` to override
this deliberately.

`v1.jsonl` at 40 rows always trips this check.

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

## Changelog

- 2026-08-24: Added 18 real-world noise rows (rw_*) simulating actual
  forwarded WhatsApp messages — abbreviations, code-mixing, DLT headers,
  OCR artifacts. These test robustness on realistic input, not just clean
  text.
  - Row `id`s use the `rw_*` prefix (not `v2-*`) so they're easy to filter.
  - The task's original field set (`id`/`text`/`lang`/`label`/`category`)
    was translated into the real 11-field v2 schema so `eval/run.py`
    actually scores these rows instead of silently skipping them (see
    "Schema" above) — `category` values were mapped to the closest
    existing v2 category (e.g. a courier/customs scam → `phishing_link`,
    which `taxonomy_map.py` already resolves to `courier_parcel` via a
    keyword match) rather than inventing new category names outside the
    fixed vocabulary.
  - 8 additional realistic scenarios beyond the original 18 were added in
    the same batch (`rw_scam_10`–`rw_scam_14`, `rw_leg_09`–`rw_leg_10`,
    `rw_unc_02`): a fake-medical-emergency money request, a WhatsApp-account
    phishing message, an income-tax "arrest warrant" call-back scam, a
    prepaid-fee work-from-home job scam, a UPI QR "scan to receive
    cashback" scam (a distinct mechanism from the existing UPI
    collect-request rows — this one baits a PIN entry via a fake incoming
    payment), a legitimate IRCTC PNR confirmation, a legitimate
    forwarded office-holiday notice (hard negative — informal tone,
    forwarded, but genuinely benign), and a genuine public scam-awareness
    forward (unclear — warns about scams rather than being one).
