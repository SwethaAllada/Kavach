# Kavach — Privacy

Kavach is a citizen safety tool. Personal messages passed through it stay
private. This document is the authoritative statement of what we store and
what we do not.

## What we STORE (per analysis, in a Supabase `signals` table)

Exactly five fields, plus a server-side timestamp:

| Field               | Type           | Example                | Notes                                        |
|---------------------|----------------|------------------------|----------------------------------------------|
| `scam_type`         | text           | `digital_arrest`       | Category label from a fixed taxonomy         |
| `risk_bucket`       | text           | `high`                 | `low` (<40) / `medium` (40–69) / `high` (≥70) — the raw risk score is **not** stored |
| `detected_language` | text (2-char)  | `hi`                   | `en` / `hi` / `te`                            |
| `decision_source`   | text           | `rules+llm+rag`        | Which layer decided                          |
| `fallback_used`     | boolean        | `false`                | Whether rules-only fallback was taken        |
| `created_at`        | timestamptz    | server-generated       | Set by Postgres `default now()` — we do not send it |

The complete whitelist is enforced in code in
[`backend/core/privacy.py`](../backend/core/privacy.py) via
`to_anonymized_record()`, backed by a unit test
(`test_to_anonymized_record_strips_everything_but_whitelist`) that fails the
build if any user-supplied text can appear in the record.

## What we DO NOT STORE — ever

The following are **read at analysis time and then discarded**. None of them
appear in the anonymized record, the store, the logs, or any downstream
system:

- The user's raw message text.
- Anything derived from that text: `prefilled_summary`, `explanation`,
  `recommended_action`.
- `matched_indicators` — the exact phrases from the user's message that
  matched a KB pattern. These echo user phrasing and are not persisted.
- Any URLs, phone numbers, UPI IDs, or bank references extracted from the
  message.
- User identity of any kind: no user ID, no session ID, no cookies, no email.
- Network identity: no IP address, no `User-Agent`, no headers.
- The raw risk score (0–100). Only the `low` / `medium` / `high` bucket.

## Why (the pitch line)

**Aligned with India's DPDP Act §5 (purpose limitation) and §8(3) (data
minimization).** We collect only the minimum necessary to compute local scam
trends, and the schema itself makes it impossible to reconstruct an individual
message from a row.

## Verification

You can verify these guarantees three ways:

1. **Read `to_anonymized_record`** — one file, 60 lines, single whitelist
   constant.
2. **Run the test suite** — `test_to_anonymized_record_strips_everything_but_whitelist`
   explicitly asserts that user phrases, URLs, phone numbers, and derived
   text cannot appear in the record even when the input verdict has them.
3. **Inspect the DDL** — the `signals` table has exactly six columns (five
   whitelisted fields plus `created_at`). There is no free-form `payload`
   column, no `metadata` JSON blob, no `raw_text` column.

## Failure mode

If the Supabase store is unreachable, `/analyze` still returns a full verdict
to the user — telemetry is fire-and-forget and its failure is swallowed.
`GET /trends` returns a valid empty shape with `"status": "unavailable"`
rather than a 500. No user action ever depends on the store being up.

## Where to look in the code

- Whitelist + record construction: `backend/core/privacy.py`
- Insert + aggregation (never blocks, never raises): `backend/services/store.py`
- Wiring at the end of `analyze()`: `backend/services/classifier.py` (step 6)
- Route: `backend/routes/trends.py`
- Frontend dashboard: `frontend/src/components/TrendsDashboard.jsx`
