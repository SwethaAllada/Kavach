"""Regenerates data/scam_kb.json from data/kb/*.yaml.

data/kb/*.yaml is the source of truth for the RAG knowledge base — one file
per entry, easy to review/diff in a PR. data/scam_kb.json is the compiled
artifact services/rag.py actually loads at runtime (see rag.py's _KB_PATH).
Before this script existed there was no way to regenerate scam_kb.json from
the yaml sources, so an edited .yaml could silently drift from what RAG
actually serves. Run this after any change under data/kb/.

Usage:
    python scripts/build_kb.py            # write data/scam_kb.json
    python scripts/build_kb.py --check     # exit 1 if scam_kb.json is stale
                                            # (CI-friendly, makes no changes)

Entries are sorted by `id` for a deterministic, reviewable diff — this may
reorder existing entries relative to the current data/scam_kb.json (which
was hand-assembled in a different order). services/rag.py's retrieve()
always re-sorts its results by similarity score before returning them, so
entry order in the JSON file does not affect RAG behavior; the sort here is
purely to make future diffs of scam_kb.json small and readable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KB_DIR = ROOT / "data" / "kb"
OUTPUT_PATH = ROOT / "data" / "scam_kb.json"

_REQUIRED_KEYS = {
    "id", "category", "title", "indicators", "why_scam", "safe_action",
    "source", "languages",
}


def _load_yaml(path: Path) -> dict:
    import yaml

    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping, got {type(data).__name__}")
    missing = _REQUIRED_KEYS - data.keys()
    if missing:
        raise ValueError(f"{path}: missing required keys {sorted(missing)}")
    return data


def build() -> list[dict]:
    if not KB_DIR.is_dir():
        raise FileNotFoundError(f"{KB_DIR} does not exist")

    entries = []
    seen_ids: set[str] = set()
    for path in sorted(KB_DIR.glob("*.yaml")):
        entry = _load_yaml(path)
        entry_id = entry["id"]
        if entry_id in seen_ids:
            raise ValueError(f"duplicate id {entry_id!r} (from {path})")
        seen_ids.add(entry_id)
        entries.append(entry)

    entries.sort(key=lambda e: e["id"])
    return entries


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check", action="store_true",
        help="Don't write; exit 1 if data/scam_kb.json is stale relative to data/kb/*.yaml",
    )
    args = ap.parse_args(argv)

    entries = build()
    new_content = json.dumps(entries, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        current = OUTPUT_PATH.read_text(encoding="utf-8") if OUTPUT_PATH.exists() else None
        if current != new_content:
            print(
                f"STALE: {OUTPUT_PATH} does not match data/kb/*.yaml. "
                f"Run `python scripts/build_kb.py` to regenerate.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {OUTPUT_PATH} is up to date ({len(entries)} entries).")
        return 0

    OUTPUT_PATH.write_text(new_content, encoding="utf-8")
    print(f"Wrote {OUTPUT_PATH} ({len(entries)} entries).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
