"""Kavach eval harness v2 — scores eval/datasets/*.jsonl against the CURRENT
engine (backend.services.classifier.analyze), unmodified.

Distinct from eval/run_eval.py (the original harness, left untouched). This
script implements the v1 dataset schema documented in eval/datasets/README.md
and scores every row TWICE:

  1. "with_sender"    — sender passed to analyze() as the structured `sender`
                        kwarg, alongside `text`. Never concatenated into the
                        message body — the engine has no sender parser yet,
                        so a header glued into the text would just be read
                        as message content and confound the comparison. Only
                        scores rows with sender_type == "dlt_header" — a
                        message with no real header has nothing to strip, so
                        scoring it here would be indistinguishable from
                        sender_stripped and would just dilute the numbers.
  2. "sender_stripped" — sender=None, text alone, exactly as a
                          WhatsApp-forwarded message usually arrives (no
                          header, no visible sender). Scores every row.

Both passes are reported side by side so a swing in headline metrics between
them is visible instead of hidden in a single blended number.

Every metric is ALSO split three ways by the row's `synthetic` field:
  - "all"       — every scored row, mixed. Sanity total only.
  - "synthetic" — REGRESSION BASELINE. Generated text; tells you if a rule
                  change broke something, never quote this externally.
  - "real"      — rows with synthetic=false (verbatim extracts, real_phone
                  submissions). The only segment safe for a deck/README.
Each printed block and each key in the JSON output is labeled with which
segment it is, so a number can't be lifted out of context by accident.

Usage:
    python eval/run.py [--dataset eval/datasets/v1.jsonl] [--max-fpr 0.05]
                        [--baseline] [--limit N] [--risk-threshold 40]

Run from the project root so relative paths resolve.
Exit code 1 if the FPR-on-legit headline (either pass) exceeds --max-fpr,
so this can gate CI later.

`--baseline` writes results/baseline.json — reserve that name for a run over
the FULL dataset. Any run under 200 rows, or with a class below 15% of the
set, is a smoke test: it prints a loud warning and writes results/smoke.json
instead, even if --baseline was passed, so a 40-row number never gets
filed under the name reviewers will trust as the real baseline.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from services.classifier import analyze  # noqa: E402

from taxonomy_map import map_row_to_scam_type  # noqa: E402

VALID_LABELS = {"legit", "scam", "unclear"}
VALID_SENDER_TYPES = {"dlt_header", "mobile_10d", "intl", "shortcode", "unknown"}
VALID_ASK_CLASSES = {
    "none", "click", "call_back", "share_credential", "make_payment", "install_app",
}

PASS_WITH_SENDER = "with_sender"
PASS_SENDER_STRIPPED = "sender_stripped"


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------


def load_dataset(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"WARN: skipping malformed line {i}: {e}", file=sys.stderr)
                continue
            missing = {
                "id", "text", "sender", "sender_type", "lang", "label",
                "category", "ask_class", "hard_negative", "source", "synthetic",
            } - row.keys()
            if missing:
                print(f"WARN: row {row.get('id', i)} missing fields {missing}, skipping", file=sys.stderr)
                continue
            rows.append(row)
    return rows


def _has_real_header(row: dict) -> bool:
    """True only if this row carries an actual sender header worth scoring
    with vs. without. `sender_type` values other than dlt_header (mobile
    number, intl, shortcode, unknown) are not a "header" in the sense this
    comparison cares about — a bare 10-digit number or "unknown" gives the
    engine nothing structurally different to condition on."""
    sender = row.get("sender")
    return row.get("sender_type") == "dlt_header" and bool(sender) and sender != "unknown"


def _sender_for_pass(row: dict, pass_name: str) -> str | None:
    """with_sender: the row's sender field, passed structurally.
    sender_stripped: None, mimicking a WhatsApp forward that dropped the
    header/number. Never merged into `text` — see module docstring."""
    if pass_name == PASS_SENDER_STRIPPED:
        return None
    return row["sender"]


# ---------------------------------------------------------------------------
# Scoring one row
# ---------------------------------------------------------------------------


def predict_one(text: str, language: str | None, sender: str | None, risk_threshold: int) -> dict:
    """Call the real engine, unmodified. Returns a normalized prediction."""
    try:
        verdict = analyze(text, language=language, sender=sender)
    except Exception as e:
        return {
            "ok": False,
            "predicted_label": "unclear",
            "predicted_scam_type": None,
            "risk": None,
            "confidence": None,
            "decision_source": "error",
            "error": f"{type(e).__name__}: {e}",
        }

    scam_type = verdict.get("scam_type")
    risk = verdict.get("risk", 0) or 0
    confidence = verdict.get("confidence")

    if scam_type == "likely_safe":
        predicted_label = "legit"
    elif risk >= risk_threshold:
        predicted_label = "scam"
    else:
        predicted_label = "unclear"

    return {
        "ok": True,
        "predicted_label": predicted_label,
        "predicted_scam_type": scam_type,
        "risk": risk,
        "confidence": confidence,
        "decision_source": verdict.get("decision_source"),
        "error": None,
    }


def evaluate_pass(rows: list[dict], pass_name: str, risk_threshold: int) -> list[dict]:
    """sender_stripped scores every row. with_sender only scores rows that
    actually carry a real header (see _has_real_header) — scoring a row with
    sender="unknown" under "with_sender" would silently pass sender=None
    either way, making it indistinguishable from sender_stripped while still
    diluting the headline numbers."""
    out = []
    for row in rows:
        if pass_name == PASS_WITH_SENDER and not _has_real_header(row):
            continue
        sender = _sender_for_pass(row, pass_name)
        pred = predict_one(row["text"], row.get("lang"), sender, risk_threshold)
        out.append({**row, **pred, "pass": pass_name, "sender_used": sender})
    return out


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

# Every metric block is computed three ways. This label is embedded in the
# output so a number can never be quoted without knowing which one it is:
#   "all"       — every scored row, synthetic + real mixed. Not a clean
#                 signal either way — mostly useful as a sanity total.
#   "synthetic" — REGRESSION BASELINE ONLY. Generated text was written to hit
#                 specific patterns; a change in this number says whether a
#                 rule/prompt change broke something that used to work. Do
#                 not put this number in a deck or README.
#   "real"      — the only segment that can be quoted externally (deck,
#                 README, pitch). Rows with synthetic=false: verbatim
#                 extracts and real_phone submissions.
SEGMENT_ALL = "all"
SEGMENT_SYNTHETIC = "synthetic"
SEGMENT_REAL = "real"

SEGMENT_LABELS = {
    SEGMENT_ALL: "ALL (mixed — sanity total only)",
    SEGMENT_SYNTHETIC: "SYNTHETIC (regression baseline — NOT for deck/README)",
    SEGMENT_REAL: "REAL (validation subset — the only one safe to quote)",
}


def _segment(results: list[dict], segment: str) -> list[dict]:
    if segment == SEGMENT_ALL:
        return results
    if segment == SEGMENT_SYNTHETIC:
        return [r for r in results if r.get("synthetic")]
    if segment == SEGMENT_REAL:
        return [r for r in results if not r.get("synthetic")]
    raise ValueError(f"unknown segment {segment!r}")


def compute_metrics(results: list[dict]) -> dict:
    ok = [r for r in results if r["ok"]]
    total = len(results)

    legit_rows = [r for r in results if r["label"] == "legit"]
    legit_hard_neg = [r for r in legit_rows if r.get("hard_negative")]
    legit_soft = [r for r in legit_rows if not r.get("hard_negative")]

    def fpr_of(rows: list[dict]) -> dict:
        n = len(rows)
        fp = sum(1 for r in rows if r["ok"] and r["predicted_label"] == "scam")
        return {"n": n, "false_positives": fp, "fpr": round(fp / n, 4) if n else 0.0}

    fpr_all = fpr_of(legit_rows)
    fpr_hard = fpr_of(legit_hard_neg)
    fpr_soft = fpr_of(legit_soft)

    scam_rows = [r for r in results if r["label"] == "scam"]
    scam_recall_hit = sum(1 for r in scam_rows if r["ok"] and r["predicted_label"] == "scam")
    scam_recall = round(scam_recall_hit / len(scam_rows), 4) if scam_rows else 0.0

    # Grouped by the engine's SCAM_TAXONOMY (via taxonomy_map.py), not the
    # raw v2 dataset `category` field — several v2 categories (otp, promo,
    # txn_alert, phishing_link, job_lottery) mix multiple engine-facing scam
    # types under one dataset theme name, so a raw-category recall table
    # would group unrelated engine behavior together. See
    # eval/taxonomy_map.py for the mapping and its documented judgment calls.
    per_category_recall = {}
    for cat in sorted(set(map_row_to_scam_type(r) for r in scam_rows)):
        cat_rows = [r for r in scam_rows if map_row_to_scam_type(r) == cat]
        hit = sum(1 for r in cat_rows if r["ok"] and r["predicted_label"] == "scam")
        per_category_recall[cat] = {
            "support": len(cat_rows),
            "recall": round(hit / len(cat_rows), 4) if cat_rows else 0.0,
        }

    predicted_scam = [r for r in ok if r["predicted_label"] == "scam"]
    scam_precision_hit = sum(1 for r in predicted_scam if r["label"] == "scam")
    scam_precision = round(scam_precision_hit / len(predicted_scam), 4) if predicted_scam else 0.0

    abstain_count = sum(1 for r in ok if r["predicted_label"] == "unclear")
    abstain_rate = round(abstain_count / total, 4) if total else 0.0

    confusion: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        pred = r["predicted_label"] if r["ok"] else "error"
        confusion[r["label"]][pred] += 1

    errors = sum(1 for r in results if not r["ok"])

    return {
        "total": total,
        "ok": len(ok),
        "errors": errors,
        "fpr_legit_headline": fpr_all,
        "fpr_legit_hard_negative": fpr_hard,
        "fpr_legit_soft": fpr_soft,
        "scam_recall_overall": scam_recall,
        "scam_recall_by_category": per_category_recall,
        "scam_precision": scam_precision,
        "abstain_rate": abstain_rate,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
    }


def compute_all_segments(results: list[dict]) -> dict[str, dict]:
    """Compute the all/synthetic/real metric blocks for one pass's results."""
    return {seg: compute_metrics(_segment(results, seg)) for seg in SEGMENT_LABELS}


# ---------------------------------------------------------------------------
# Sample-size sanity check
# ---------------------------------------------------------------------------


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


MIN_ROWS_FOR_BASELINE = 200
MIN_CLASS_SHARE = 0.15


def check_sample_size(rows: list[dict]) -> list[str]:
    """Return a list of warning strings if this dataset is too small or too
    imbalanced to be quoted as a real baseline. Empty list = looks fine."""
    warnings = []
    n = len(rows)
    if n < MIN_ROWS_FOR_BASELINE:
        warnings.append(
            f"only {n} rows (< {MIN_ROWS_FOR_BASELINE}) — this is a SMOKE TEST, "
            f"not a baseline. On ~{n} rows one flipped row moves headline "
            f"metrics by ~{round(100 / max(n, 1), 1)} points."
        )
    label_counts = Counter(r["label"] for r in rows)
    for label in sorted(VALID_LABELS):
        share = label_counts.get(label, 0) / n if n else 0.0
        if share < MIN_CLASS_SHARE:
            warnings.append(
                f"label='{label}' is only {_fmt_pct(share)} of rows "
                f"({label_counts.get(label, 0)}/{n}), below the {_fmt_pct(MIN_CLASS_SHARE)} floor — "
                f"metrics for this class are noisy."
            )
    return warnings


def print_side_by_side(metrics_a: dict, metrics_b: dict, label_a: str, label_b: str) -> None:
    label_a_hdr = f"{label_a} (n={metrics_a['total']})"
    label_b_hdr = f"{label_b} (n={metrics_b['total']})"
    print(f"\n{'Metric':40s} {label_a_hdr:>18s} {label_b_hdr:>18s}")
    print("-" * 78)

    def row(name: str, va: Any, vb: Any) -> None:
        print(f"{name:40s} {str(va):>18s} {str(vb):>18s}")

    row(
        "FPR on legit (HEADLINE)",
        _fmt_pct(metrics_a["fpr_legit_headline"]["fpr"]),
        _fmt_pct(metrics_b["fpr_legit_headline"]["fpr"]),
    )
    row(
        "  of which hard_negative=true",
        _fmt_pct(metrics_a["fpr_legit_hard_negative"]["fpr"]),
        _fmt_pct(metrics_b["fpr_legit_hard_negative"]["fpr"]),
    )
    row(
        "  of which hard_negative=false",
        _fmt_pct(metrics_a["fpr_legit_soft"]["fpr"]),
        _fmt_pct(metrics_b["fpr_legit_soft"]["fpr"]),
    )
    row("Scam recall (overall)", _fmt_pct(metrics_a["scam_recall_overall"]), _fmt_pct(metrics_b["scam_recall_overall"]))
    row("Precision on Scam verdict", _fmt_pct(metrics_a["scam_precision"]), _fmt_pct(metrics_b["scam_precision"]))
    row("Abstain rate", _fmt_pct(metrics_a["abstain_rate"]), _fmt_pct(metrics_b["abstain_rate"]))
    row("Errors", metrics_a["errors"], metrics_b["errors"])

    print("\nScam recall by category:")
    cats = sorted(set(metrics_a["scam_recall_by_category"]) | set(metrics_b["scam_recall_by_category"]))
    print(f"  {'category':25s} {label_a:>10s} {label_b:>10s}  support")
    for cat in cats:
        a = metrics_a["scam_recall_by_category"].get(cat, {"recall": 0.0, "support": 0})
        b = metrics_b["scam_recall_by_category"].get(cat, {"recall": 0.0, "support": 0})
        print(f"  {cat:25s} {_fmt_pct(a['recall']):>10s} {_fmt_pct(b['recall']):>10s}  {a['support']}")

    for name, m in ((label_a, metrics_a), (label_b, metrics_b)):
        print(f"\nConfusion matrix — {name} (rows=true label, cols=predicted):")
        labels = sorted(VALID_LABELS | {"error"})
        print(f"  {'':10s} " + " ".join(f"{p:>8s}" for p in labels))
        for true_label in sorted(VALID_LABELS):
            counts = m["confusion_matrix"].get(true_label, {})
            print(f"  {true_label:10s} " + " ".join(f"{counts.get(p, 0):>8d}" for p in labels))


def print_all_segments(segments_with_sender: dict[str, dict], segments_stripped: dict[str, dict]) -> None:
    """Print the with_sender vs. sender_stripped comparison three times —
    once per segment (all/synthetic/real) — each block loudly labeled so a
    number can't be lifted out of context later."""
    for seg in (SEGMENT_ALL, SEGMENT_SYNTHETIC, SEGMENT_REAL):
        print("\n" + "=" * 78)
        print(f"SEGMENT: {SEGMENT_LABELS[seg]}")
        print("=" * 78)
        print_side_by_side(
            segments_with_sender[seg], segments_stripped[seg],
            PASS_WITH_SENDER, PASS_SENDER_STRIPPED,
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kavach eval harness v2 (dual sender scoring)")
    ap.add_argument("--dataset", default=str(ROOT / "eval" / "datasets" / "v1.jsonl"))
    ap.add_argument("--outdir", default=str(ROOT / "eval" / "results"))
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--risk-threshold", type=int, default=40)
    ap.add_argument("--max-fpr", type=float, default=0.10, help="Exit 1 if headline legit FPR exceeds this, in either pass")
    ap.add_argument(
        "--baseline", action="store_true",
        help="Write results/baseline.json — REFUSED (downgraded to smoke.json) if the "
             "dataset is too small or too imbalanced; see --force-baseline",
    )
    ap.add_argument(
        "--force-baseline", action="store_true",
        help="Write results/baseline.json even if the sample-size check would otherwise "
             "downgrade it to smoke.json. Use only if you have a deliberate reason.",
    )
    args = ap.parse_args(argv)

    dataset_path = Path(args.dataset)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    rows = load_dataset(dataset_path)
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        print("No rows to evaluate.", file=sys.stderr)
        return 2

    print(f"# Kavach eval v2 — {len(rows)} rows from {dataset_path}")

    size_warnings = check_sample_size(rows)
    is_smoke = bool(size_warnings) and not args.force_baseline
    if size_warnings:
        print("\n" + "!" * 78, file=sys.stderr)
        print("! SAMPLE SIZE WARNING — DO NOT QUOTE THIS RUN AS A BASELINE", file=sys.stderr)
        print("!" * 78, file=sys.stderr)
        for w in size_warnings:
            print(f"! {w}", file=sys.stderr)
        if is_smoke and args.baseline:
            print("! --baseline requested but downgraded to smoke.json (pass --force-baseline to override)", file=sys.stderr)
        print("!" * 78 + "\n", file=sys.stderr)

    header_rows = [r for r in rows if _has_real_header(r)]
    print(
        f"# with_sender pass: {len(header_rows)}/{len(rows)} rows have a real "
        f"sender_type=dlt_header — only those are scored under with_sender; "
        f"sender_stripped always scores all {len(rows)} rows."
    )

    results_with_sender = evaluate_pass(rows, PASS_WITH_SENDER, args.risk_threshold)
    results_stripped = evaluate_pass(rows, PASS_SENDER_STRIPPED, args.risk_threshold)

    segments_with_sender = compute_all_segments(results_with_sender)
    segments_stripped = compute_all_segments(results_stripped)

    real_n = sum(1 for r in rows if not r.get("synthetic"))
    print(f"# real (synthetic=false) rows in this dataset: {real_n}/{len(rows)}")
    if real_n == 0:
        print("# NOTE: 0 real rows — the REAL segment below is empty and cannot be quoted anywhere.", file=sys.stderr)

    print_all_segments(segments_with_sender, segments_stripped)

    payload = {
        "dataset": str(dataset_path),
        "is_smoke_test": is_smoke,
        "sample_size_warnings": size_warnings,
        "segment_labels": SEGMENT_LABELS,
        "config": {
            "risk_threshold": args.risk_threshold,
            "max_fpr": args.max_fpr,
            "rows": len(rows),
            "real_rows": real_n,
        },
        "passes": {
            PASS_WITH_SENDER: {
                "segments": segments_with_sender,
                "results": results_with_sender,
            },
            PASS_SENDER_STRIPPED: {
                "segments": segments_stripped,
                "results": results_stripped,
            },
        },
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload["generated_at"] = timestamp
    timestamped_path = outdir / f"{timestamp}.json"
    with timestamped_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"\nWrote: {timestamped_path}")

    if args.baseline:
        named_path = outdir / ("smoke.json" if is_smoke else "baseline.json")
        with named_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {named_path}")

    # Gate on the ALL segment (every scored row) — this is the full-run
    # number and matches the pre-segment-split gate behavior. It intentionally
    # does NOT gate on the real-only segment: with few real rows today, that
    # segment is too small to be a reliable CI gate on its own.
    worst_fpr = max(
        segments_with_sender[SEGMENT_ALL]["fpr_legit_headline"]["fpr"],
        segments_stripped[SEGMENT_ALL]["fpr_legit_headline"]["fpr"],
    )
    if worst_fpr > args.max_fpr:
        print(
            f"\nFAIL: legit FPR (ALL segment) {_fmt_pct(worst_fpr)} exceeds --max-fpr {_fmt_pct(args.max_fpr)}",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: legit FPR (ALL segment) {_fmt_pct(worst_fpr)} within --max-fpr {_fmt_pct(args.max_fpr)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
