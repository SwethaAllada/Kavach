"""Kavach eval harness v2 — scores eval/datasets/*.jsonl against the CURRENT
engine (backend.services.classifier.analyze), unmodified.

Distinct from eval/run_eval.py (the original harness, left untouched). This
script implements the v1 dataset schema documented in eval/datasets/README.md
and scores every row TWICE:

  1. "with_sender"    — sender prepended to the text as a header line.
  2. "sender_stripped" — text alone, exactly as a WhatsApp-forwarded message
                          usually arrives (no header, no visible sender).

Both passes are reported side by side so a swing in headline metrics between
them is visible instead of hidden in a single blended number.

Usage:
    python eval/run.py [--dataset eval/datasets/v1.jsonl] [--max-fpr 0.05]
                        [--baseline] [--limit N] [--risk-threshold 40]

Run from the project root so relative paths resolve.
Exit code 1 if the FPR-on-legit headline (either pass) exceeds --max-fpr,
so this can gate CI later.
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
                "category", "ask_class", "hard_negative", "source",
            } - row.keys()
            if missing:
                print(f"WARN: row {row.get('id', i)} missing fields {missing}, skipping", file=sys.stderr)
                continue
            rows.append(row)
    return rows


def _build_text_for_pass(row: dict, pass_name: str) -> str:
    """with_sender: prepend a sender header line, mimicking a raw inbound
    message. sender_stripped: the bare text, mimicking a WhatsApp forward
    that dropped the header/number."""
    if pass_name == PASS_SENDER_STRIPPED:
        return row["text"]
    sender = row.get("sender") or "unknown"
    return f"From: {sender}\n{row['text']}"


# ---------------------------------------------------------------------------
# Scoring one row
# ---------------------------------------------------------------------------


def predict_one(text: str, language: str | None, risk_threshold: int) -> dict:
    """Call the real engine, unmodified. Returns a normalized prediction."""
    try:
        verdict = analyze(text, language=language)
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
    out = []
    for row in rows:
        text = _build_text_for_pass(row, pass_name)
        pred = predict_one(text, row.get("lang"), risk_threshold)
        out.append({**row, **pred, "pass": pass_name})
    return out


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


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

    per_category_recall = {}
    for cat in sorted(set(r["category"] for r in scam_rows)):
        cat_rows = [r for r in scam_rows if r["category"] == cat]
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


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def print_side_by_side(metrics_a: dict, metrics_b: dict, label_a: str, label_b: str) -> None:
    print(f"\n{'Metric':40s} {label_a:>18s} {label_b:>18s}")
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
    ap.add_argument("--baseline", action="store_true", help="Also write results/baseline.json")
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

    results_with_sender = evaluate_pass(rows, PASS_WITH_SENDER, args.risk_threshold)
    results_stripped = evaluate_pass(rows, PASS_SENDER_STRIPPED, args.risk_threshold)

    metrics_with_sender = compute_metrics(results_with_sender)
    metrics_stripped = compute_metrics(results_stripped)

    print_side_by_side(metrics_with_sender, metrics_stripped, PASS_WITH_SENDER, PASS_SENDER_STRIPPED)

    payload = {
        "dataset": str(dataset_path),
        "config": {
            "risk_threshold": args.risk_threshold,
            "max_fpr": args.max_fpr,
            "rows": len(rows),
        },
        "passes": {
            PASS_WITH_SENDER: {
                "metrics": metrics_with_sender,
                "results": results_with_sender,
            },
            PASS_SENDER_STRIPPED: {
                "metrics": metrics_stripped,
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
        baseline_path = outdir / "baseline.json"
        with baseline_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"Wrote: {baseline_path}")

    worst_fpr = max(
        metrics_with_sender["fpr_legit_headline"]["fpr"],
        metrics_stripped["fpr_legit_headline"]["fpr"],
    )
    if worst_fpr > args.max_fpr:
        print(
            f"\nFAIL: legit FPR {_fmt_pct(worst_fpr)} exceeds --max-fpr {_fmt_pct(args.max_fpr)}",
            file=sys.stderr,
        )
        return 1

    print(f"\nOK: legit FPR {_fmt_pct(worst_fpr)} within --max-fpr {_fmt_pct(args.max_fpr)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
