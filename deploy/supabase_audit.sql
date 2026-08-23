-- Kavach — legal-admissibility audit trail table.
-- Paste this whole file into the Supabase SQL editor and run.
--
-- Separate table from public.signals (deploy/supabase.sql), with a
-- deliberately wider field contract: this table exists so a user or law
-- enforcement can later be shown "here is the analysis record for case
-- KAV-YYYYMMDD-XXXX, generated at this timestamp, with this confidence
-- level and these matched pattern sources." It still never stores raw
-- message text — input_hash is a one-way SHA-256 digest of the input,
-- and matched_pattern_ids is a comma-separated list of KB entry IDs
-- (e.g. "DA-01,DA-03"), not the matched text itself.

create table if not exists public.audit_log (
    case_id             text primary key,
    scam_type           text,
    risk_bucket         text,
    confidence_bucket   text,   -- 'high' (>0.8), 'medium' (0.5-0.8), 'low' (<0.5)
    decision_source     text,
    detected_language   text,
    matched_pattern_ids text,   -- comma-separated KB entry IDs, e.g. "DA-01,DA-03"
    fallback_used       boolean,
    input_hash          text,   -- SHA-256 hex digest of the input text, NOT the text
    created_at          timestamptz not null default now()
);

-- GET /case/{case_id} looks up by primary key directly, but this index
-- keeps any future recency-ordered listing cheap too.
create index if not exists audit_log_created_at_idx
    on public.audit_log (created_at desc);

-- Turn on Row-Level Security. The Kavach backend uses the `service_role` key
-- which bypasses RLS server-side; the anon key never sees this table.
alter table public.audit_log enable row level security;
