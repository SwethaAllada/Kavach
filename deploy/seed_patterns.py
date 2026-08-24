"""One-off seeding script: load data/scam_kb.json into Supabase's
public.scam_patterns table (deploy/supabase_scam_patterns.sql must already
be applied).

Run from the repo root:
    python deploy/seed_patterns.py
or from backend/:
    python ../deploy/seed_patterns.py

Idempotent: uses PostgREST's `Prefer: resolution=ignore-duplicates` header on
the POST, which maps directly to `INSERT ... ON CONFLICT (id) DO NOTHING` —
safe to re-run; rows that already exist (by primary key `id`) are silently
skipped rather than erroring or duplicating.

This is a standalone CLI script, not part of the FastAPI app — plain
print() for status output, no logging module, no test coverage expected.
It is NOT run automatically by anything in backend/; a human runs it once
after reviewing deploy/supabase_scam_patterns.sql.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

# This script lives in deploy/, not backend/, so backend's packages
# (core.config, etc.) aren't importable by default. Add backend/ to
# sys.path the same way backend/tests/*.py add backend's parent for their
# own imports.
_BACKEND_DIR = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(_BACKEND_DIR))

import httpx  # noqa: E402

from core.config import settings  # noqa: E402

_KB_PATH = Path(__file__).resolve().parents[1] / "data" / "scam_kb.json"
_TABLE = "scam_patterns"
_TIMEOUT_S = 15.0


def _rest_url() -> str:
    base = settings.supabase_url.rstrip("/")
    return f"{base}/rest/v1/{_TABLE}"


def _headers() -> dict:
    return {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
        # Maps to ON CONFLICT (id) DO NOTHING: rows whose primary key
        # already exists are silently skipped rather than erroring.
        "Prefer": "resolution=ignore-duplicates,return=representation",
    }


def _load_kb() -> list[dict]:
    with _KB_PATH.open("r", encoding="utf-8") as f:
        data = __import__("json").load(f)
    if not isinstance(data, list):
        raise ValueError(f"{_KB_PATH} did not contain a JSON list")
    return data


def _to_row(entry: dict) -> dict:
    now_iso = datetime.now(timezone.utc).isoformat()
    return {
        "id": entry.get("id"),
        "category": entry.get("category"),
        "title": entry.get("title"),
        "indicators": entry.get("indicators") or [],
        "why_scam": entry.get("why_scam", ""),
        "safe_action": entry.get("safe_action", ""),
        "source": entry.get("source", ""),
        "languages": entry.get("languages") or ["en"],
        "status": "approved",
        "submission_count": 1,
        "approved_at": now_iso,
    }


def main() -> int:
    if not settings.supabase_url or not settings.supabase_service_key:
        print("ERROR: SUPABASE_URL / SUPABASE_SERVICE_KEY are not set. Aborting.")
        return 1

    entries = _load_kb()
    print(f"Loaded {len(entries)} entries from {_KB_PATH}")

    inserted = 0
    skipped = 0
    errored = 0

    url = _rest_url()
    headers = _headers()

    with httpx.Client(timeout=_TIMEOUT_S) as client:
        for entry in entries:
            row = _to_row(entry)
            try:
                resp = client.post(url, headers=headers, json=row)
                if resp.status_code in (200, 201):
                    body = resp.json() if resp.content else []
                    if isinstance(body, list) and body:
                        inserted += 1
                    else:
                        # 201 with an empty body under
                        # resolution=ignore-duplicates means the row already
                        # existed and was skipped.
                        skipped += 1
                elif resp.status_code == 409:
                    skipped += 1
                else:
                    errored += 1
                    print(
                        f"  ERROR inserting {row.get('id')}: "
                        f"HTTP {resp.status_code} {resp.text[:200]}"
                    )
            except Exception as e:
                errored += 1
                print(f"  ERROR inserting {row.get('id')}: {e}")

    print("---")
    print(f"Inserted: {inserted}")
    print(f"Skipped (already existing): {skipped}")
    print(f"Errored: {errored}")
    return 0 if errored == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
