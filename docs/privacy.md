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

## Why (DPDP alignment)

The five-field whitelist is not a happy accident — it is a deliberate design
choice mapped to India's Digital Personal Data Protection Act, 2023:

- **§4 lawful purpose / §5 purpose limitation.** Kavach's sole purpose is to
  detect scam attempts on messages the user hands to us. The `signals` row
  serves *aggregate trend intelligence* (which scam categories are trending
  in which languages) — nothing else. There is no cross-purpose profile,
  no ad-targeting field, no linkage to other systems.
- **§8(3) accuracy & minimization.** The stored fields are the coarsest
  categorical labels that still give us a useful dashboard. Notably we
  store a `risk_bucket` (low/medium/high), not the raw risk score, and
  we don't store the raw message that would let us re-derive one.
- **Data-principal identifiability.** DPDP defines personal data as data
  relating to an *identifiable* individual. The `signals` row contains no
  identifier: no IP, no session cookie, no phone number, no user ID, no
  device fingerprint. Every row is symmetric with every other row of the
  same shape; a subpoena directed at Kavach's telemetry would return
  category counts, not a person.
- **No cross-border transfer of personal data.** Only anonymized counts
  ever leave the backend; the actual message text never leaves the request
  path.

## Retention

- The `signals` table is **append-only aggregate telemetry**. Rows are
  retained for **rolling 30 days** for the trends dashboard, then may be
  aggregated further (weekly rollup) or deleted. The `/trends` endpoint
  reads only the last 30 days by default.
- Since a row is not identifiable, there is no data-subject deletion request
  Kavach can meaningfully honor — you cannot ask us to "delete your row"
  because we do not know which row is yours. This is by design.
- If a reviewer wants to see this bounded in code: `backend/services/store.py`
  → `_fetch_rows()` sets `created_at >= now() - 30 days` in the PostgREST
  query.

## How a reviewer can verify

Four independent ways to check these claims — no need to trust the docs:

1. **Read `backend/core/privacy.py`** — one file, ~60 lines, single whitelist
   constant `_WHITELISTED_KEYS = {"scam_type", "risk_bucket",
   "detected_language", "decision_source", "fallback_used"}`. Everything the
   verdict carries beyond that is dropped by `to_anonymized_record()`.
2. **Run the test suite** —
   `test_to_anonymized_record_strips_everything_but_whitelist` explicitly
   feeds a verdict containing user phrases, URLs, phone numbers, and derived
   text into `to_anonymized_record`, then asserts none of those strings
   appear anywhere in the returned dict.
3. **Inspect the DDL** — the `signals` table (`deploy/supabase.sql`) has
   exactly six columns: the five whitelisted fields plus `created_at`.
   There is no free-form `payload` column, no `metadata` JSON blob, no
   `raw_text` column. The schema itself makes leakage impossible.
4. **Query Supabase directly** — with the `service_role` key, run
   `select * from signals` in the Supabase SQL editor. The rows have the
   six columns above and nothing else. Nowhere in that table is the string
   `"CBI"`, `"1930"`, `"Aadhaar"`, `+91<any-number>`, or any URL from any
   message any user ever analyzed.

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
