-- Kavach — user-submitted scam pattern staging table.
-- Paste this whole file into the Supabase SQL editor and run.
--
-- Deliberate exception to the "never persist message content" rule that
-- governs public.signals / public.audit_log (deploy/supabase.sql,
-- deploy/supabase_audit.sql): `submitted_text` here DOES store the raw text
-- a user voluntarily submitted via POST /patterns/submit. That rule exists
-- to protect the privacy of a message someone sent US FOR ANALYSIS (their
-- own possibly-private conversation); this table instead holds scam
-- EXAMPLES a user chose to contribute to a public knowledge base, which is
-- a fundamentally different consent context — the same way a curated
-- example in data/scam_kb.json is not "someone's private message" even
-- though it is scam-pattern text. If 3+ independent submissions in the same
-- category overlap heavily, routes/patterns.py auto-approves a NEW entry
-- into public.scam_patterns (deploy/supabase_scam_patterns.sql) derived from
-- these submissions (keywords only, not the raw text verbatim) and marks the
-- matching rows here as status='incorporated'.

create table if not exists public.pending_patterns (
  id                uuid default gen_random_uuid() primary key,
  submitted_text    text not null,
  detected_category text,
  detected_language text,
  similarity_score  float,
  status            text default 'pending',
  submitted_via     text default 'api',
  created_at        timestamptz default now()
);

-- /patterns/submit's step 4 looks up pending rows by category + status;
-- index both to keep that read cheap as submissions accumulate.
create index if not exists pending_patterns_category_status_idx
    on public.pending_patterns(detected_category, status);

-- Turn on Row-Level Security. The Kavach backend uses the `service_role` key
-- which bypasses RLS server-side; the anon key never sees this table.
alter table public.pending_patterns enable row level security;
