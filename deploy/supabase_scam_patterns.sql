-- Kavach — crowd-verified scam pattern knowledge base table.
-- Paste this whole file into the Supabase SQL editor and run.
--
-- This table is the Supabase-backed mirror of data/scam_kb.json: it holds
-- the SAME shape of entry (id/category/title/indicators/why_scam/
-- safe_action/source/languages) that services/rag.py already scores against,
-- plus a status/submission_count/approved_at lifecycle so entries can arrive
-- two ways:
--   1. Seeded from data/scam_kb.json (deploy/seed_patterns.py) with
--      status='approved' — the original 22 curated entries.
--   2. Auto-approved at runtime by routes/patterns.py once 3+ independent
--      users report an essentially-identical new pattern (status=
--      'auto_approved') — see pending_patterns (deploy/supabase_pending_patterns.sql)
--      for the staging table those reports go through first.
--
-- Privacy note: `indicators`/`title` are short scam-pattern keywords/phrases,
-- not a specific user's message — same privacy posture as data/scam_kb.json
-- today. This table is NOT governed by the "never persist message content"
-- rule the same way `signals`/`audit_log` are, because entries here are
-- meant to be public reference material (the KB itself), not a record of
-- any one person's private conversation.

create table if not exists public.scam_patterns (
  id              text primary key,
  category        text not null,
  title           text not null,
  indicators      jsonb not null default '[]',
  why_scam        text not null,
  safe_action     text not null,
  source          text not null,
  languages       jsonb not null default '["en"]',
  status          text not null default 'approved',
  submission_count integer default 1,
  created_at      timestamptz default now(),
  approved_at     timestamptz
);

-- routes/patterns.py's duplicate-check step reads all approved-category rows;
-- this partial index keeps that scan cheap and ignores pending/rejected rows.
create index if not exists scam_patterns_category_approved_idx
    on public.scam_patterns(category) where status = 'approved';

-- /patterns/stats and /trends' pattern_intelligence key both count rows by
-- status (approved / auto_approved / pending elsewhere) — index the column
-- directly since it's the primary filter for those aggregate reads.
create index if not exists scam_patterns_status_idx
    on public.scam_patterns(status);

-- Turn on Row-Level Security. The Kavach backend uses the `service_role` key
-- which bypasses RLS server-side; the anon key never sees this table.
alter table public.scam_patterns enable row level security;
