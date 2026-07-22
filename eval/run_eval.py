"""Kavach evaluation harness.

Calls the SAME analyze() the API uses (from backend.services.classifier),
computes accuracy / precision / recall / F1 / FPR / FNR / per-class metrics
/ latency, and writes both a human report (report.md) and a machine-readable
per-row dump (results.json).

Usage:
    python eval/run_eval.py [--limit N] [--delay 1.5] [--risk-threshold 40]
                            [--dataset eval/dataset.jsonl] [--outdir eval]

Run from the project root (kavach/) so relative paths resolve.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import traceback
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

# Make `backend.services.classifier` importable without installing the backend.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

# Load the same .env the backend uses, so XAI_API_KEY is available.
try:
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:
    pass

from services.classifier import analyze  # noqa: E402


# ---------------------------------------------------------------------------
# Metrics helpers (plain Python, no sklearn)
# ---------------------------------------------------------------------------


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    sorted_v = sorted(values)
    k = (len(sorted_v) - 1) * (pct / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(sorted_v) - 1)
    return sorted_v[lo] + (sorted_v[hi] - sorted_v[lo]) * (k - lo)


# ---------------------------------------------------------------------------
# Core eval
# ---------------------------------------------------------------------------


def load_dataset(path: Path) -> list[dict]:
    rows = []
    with path.open() as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"WARN: skipping malformed line {i}: {e}", file=sys.stderr)
    return rows


def predict_one(text: str, language: str | None, risk_threshold: int) -> dict:
    """Call the real engine. Returns a normalized prediction dict."""
    t0 = time.perf_counter()
    try:
        verdict = analyze(text, language=language)
        latency = time.perf_counter() - t0
        predicted_is_scam = (
            verdict["scam_type"] != "likely_safe" and verdict["risk"] >= risk_threshold
        )
        return {
            "ok": True,
            "predicted_scam_type": verdict["scam_type"],
            "predicted_is_scam": predicted_is_scam,
            "risk": verdict["risk"],
            "confidence": verdict["confidence"],
            "decision_source": verdict["decision_source"],
            "fallback_used": verdict["fallback_used"],
            "detected_language": verdict["detected_language"],
            "latency_s": round(latency, 3),
            "error": None,
        }
    except Exception as e:
        latency = time.perf_counter() - t0
        return {
            "ok": False,
            "predicted_scam_type": None,
            "predicted_is_scam": None,
            "risk": None,
            "confidence": None,
            "decision_source": "error",
            "fallback_used": None,
            "detected_language": None,
            "latency_s": round(latency, 3),
            "error": f"{type(e).__name__}: {e}",
        }


def evaluate(rows: list[dict], delay: float, risk_threshold: int) -> list[dict]:
    results = []
    for i, row in enumerate(rows, 1):
        pred = predict_one(row["text"], row.get("language"), risk_threshold)
        entry = {
            "id": row["id"],
            "text": row["text"],
            "language": row.get("language"),
            "label_scam_type": row["label_scam_type"],
            "label_is_scam": row["is_scam"],
            **pred,
        }
        results.append(entry)
        status = "OK" if pred["ok"] else "ERR"
        print(
            f"[{i:>3}/{len(rows)}] {row['id']:14s} {status} "
            f"lang={pred['detected_language'] or '-'} "
            f"pred={pred['predicted_scam_type']!s:20s} "
            f"risk={pred['risk']!s:>4} "
            f"src={pred['decision_source']:15s} "
            f"lat={pred['latency_s']}s",
            flush=True,
        )
        if i < len(rows) and delay > 0:
            time.sleep(delay)
    return results


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def compute_metrics(results: list[dict]) -> dict:
    total = len(results)
    ok = [r for r in results if r["ok"]]
    errors = [r for r in results if not r["ok"]]

    # Multiclass accuracy (over successful predictions vs ALL rows).
    exact_type_matches = sum(
        1 for r in ok if r["predicted_scam_type"] == r["label_scam_type"]
    )
    scam_type_accuracy = exact_type_matches / total if total else 0.0

    # Binary scam-vs-legit.
    tp = fp = tn = fn = 0
    for r in ok:
        pred, label = r["predicted_is_scam"], r["label_is_scam"]
        if label and pred:
            tp += 1
        elif label and not pred:
            fn += 1
        elif not label and pred:
            fp += 1
        else:
            tn += 1

    precision, recall, f1 = _prf(tp, fp, fn)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0  # legit wrongly flagged as scam
    fnr = fn / (fn + tp) if (fn + tp) else 0.0  # scams missed

    # Per-class precision/recall/F1 on scam_type.
    per_class = {}
    all_labels = sorted(
        set(r["label_scam_type"] for r in results)
        | set(r["predicted_scam_type"] for r in ok if r["predicted_scam_type"])
    )
    for cls in all_labels:
        c_tp = sum(1 for r in ok if r["predicted_scam_type"] == cls and r["label_scam_type"] == cls)
        c_fp = sum(1 for r in ok if r["predicted_scam_type"] == cls and r["label_scam_type"] != cls)
        c_fn = sum(1 for r in ok if r["predicted_scam_type"] != cls and r["label_scam_type"] == cls)
        support = sum(1 for r in results if r["label_scam_type"] == cls)
        p, rec, cf1 = _prf(c_tp, c_fp, c_fn)
        per_class[cls] = {
            "precision": round(p, 3),
            "recall": round(rec, 3),
            "f1": round(cf1, 3),
            "support": support,
            "tp": c_tp,
            "fp": c_fp,
            "fn": c_fn,
        }

    # Confusion summary (only over successful predictions).
    correct = sum(
        1 for r in ok if r["predicted_scam_type"] == r["label_scam_type"]
    )
    wrong_type_caught_as_scam = sum(
        1
        for r in ok
        if r["label_is_scam"]
        and r["predicted_is_scam"]
        and r["predicted_scam_type"] != r["label_scam_type"]
    )
    missed_scams = fn
    false_alarms = fp

    # Latency.
    latencies = [r["latency_s"] for r in ok if r["latency_s"] is not None]
    latency_stats = {
        "n": len(latencies),
        "mean": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "median": round(statistics.median(latencies), 3) if latencies else 0.0,
        "p95": round(_percentile(latencies, 95), 3),
        "min": round(min(latencies), 3) if latencies else 0.0,
        "max": round(max(latencies), 3) if latencies else 0.0,
    }

    # Coverage: rules+llm vs rules_fallback vs error.
    coverage = Counter(r["decision_source"] for r in results)

    # Language breakdown.
    lang_breakdown = defaultdict(lambda: {"total": 0, "type_correct": 0, "binary_correct": 0})
    for r in results:
        lang = r["language"] or "?"
        lang_breakdown[lang]["total"] += 1
        if r["ok"]:
            if r["predicted_scam_type"] == r["label_scam_type"]:
                lang_breakdown[lang]["type_correct"] += 1
            if r["predicted_is_scam"] == r["label_is_scam"]:
                lang_breakdown[lang]["binary_correct"] += 1

    return {
        "total": total,
        "ok": len(ok),
        "errors": len(errors),
        "scam_type_accuracy": round(scam_type_accuracy, 3),
        "binary": {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "false_positive_rate": round(fpr, 3),
            "false_negative_rate": round(fnr, 3),
        },
        "per_class": per_class,
        "confusion": {
            "correct_type": correct,
            "wrong_type_but_caught_as_scam": wrong_type_caught_as_scam,
            "missed_scams": missed_scams,
            "false_alarms": false_alarms,
        },
        "latency": latency_stats,
        "coverage": dict(coverage),
        "by_language": {
            lang: {
                "total": v["total"],
                "type_accuracy": round(v["type_correct"] / v["total"], 3) if v["total"] else 0.0,
                "binary_accuracy": round(v["binary_correct"] / v["total"], 3) if v["total"] else 0.0,
            }
            for lang, v in lang_breakdown.items()
        },
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


def write_results_json(results: list[dict], metrics: dict, config: dict, path: Path) -> None:
    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "config": config,
        "metrics": metrics,
        "results": results,
    }
    with path.open("w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def write_report_md(metrics: dict, config: dict, path: Path) -> None:
    m = metrics
    b = m["binary"]
    lat = m["latency"]

    lines = [
        "# Kavach — Evaluation Report",
        "",
        f"**Generated:** {datetime.utcnow().isoformat()}Z",
        "",
        "## Config",
        "",
        "| Setting | Value |",
        "| --- | --- |",
        f"| Dataset | `{config['dataset']}` |",
        f"| Rows evaluated | {m['total']} |",
        f"| Successful predictions | {m['ok']} |",
        f"| Errors | {m['errors']} |",
        f"| Risk threshold (is_scam gate) | `risk >= {config['risk_threshold']}` |",
        f"| Delay between calls | {config['delay']}s |",
        f"| Limit | {config['limit'] or 'none (full run)'} |",
        f"| Model | {config['model']} |",
        "",
        "## Headline",
        "",
        f"- **Scam-type exact accuracy:** {_fmt_pct(m['scam_type_accuracy'])} ({m['confusion']['correct_type']}/{m['total']})",
        f"- **Binary scam vs. legit F1:** {b['f1']:.3f} — precision {b['precision']:.3f}, recall {b['recall']:.3f}",
        f"- **False positive rate** (legit flagged as scam): {_fmt_pct(b['false_positive_rate'])} ({b['fp']} of {b['fp'] + b['tn']} legit)",
        f"- **False negative rate** (scams missed): {_fmt_pct(b['false_negative_rate'])} ({b['fn']} of {b['fn'] + b['tp']} scams)",
        "",
        "## Confusion Summary",
        "",
        "| Bucket | Count |",
        "| --- | ---: |",
        f"| Correct scam type | {m['confusion']['correct_type']} |",
        f"| Caught as scam but wrong type | {m['confusion']['wrong_type_but_caught_as_scam']} |",
        f"| Missed scams (false negatives) | {m['confusion']['missed_scams']} |",
        f"| False alarms (legit flagged) | {m['confusion']['false_alarms']} |",
        "",
        "## Binary Classifier Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| True positives | {b['tp']} |",
        f"| False positives | {b['fp']} |",
        f"| True negatives | {b['tn']} |",
        f"| False negatives | {b['fn']} |",
        f"| Precision | {b['precision']:.3f} |",
        f"| Recall | {b['recall']:.3f} |",
        f"| F1 | {b['f1']:.3f} |",
        f"| False positive rate | {_fmt_pct(b['false_positive_rate'])} |",
        f"| False negative rate | {_fmt_pct(b['false_negative_rate'])} |",
        "",
        "## Per-Class Metrics (scam_type)",
        "",
        "| Class | Support | TP | FP | FN | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for cls, v in sorted(m["per_class"].items()):
        lines.append(
            f"| {cls} | {v['support']} | {v['tp']} | {v['fp']} | {v['fn']} | "
            f"{v['precision']:.3f} | {v['recall']:.3f} | {v['f1']:.3f} |"
        )

    lines += [
        "",
        "## Latency (seconds)",
        "",
        "| Stat | Value |",
        "| --- | ---: |",
        f"| n | {lat['n']} |",
        f"| Mean | {lat['mean']} |",
        f"| Median | {lat['median']} |",
        f"| p95 | {lat['p95']} |",
        f"| Min | {lat['min']} |",
        f"| Max | {lat['max']} |",
        "",
        "## Coverage (decision source)",
        "",
        "| Source | Count |",
        "| --- | ---: |",
    ]
    for src, cnt in sorted(m["coverage"].items(), key=lambda x: -x[1]):
        lines.append(f"| {src} | {cnt} |")

    lines += [
        "",
        "## By Language",
        "",
        "| Language | Rows | Type accuracy | Binary accuracy |",
        "| --- | ---: | ---: | ---: |",
    ]
    for lang, v in sorted(m["by_language"].items()):
        lines.append(
            f"| {lang} | {v['total']} | {_fmt_pct(v['type_accuracy'])} | "
            f"{_fmt_pct(v['binary_accuracy'])} |"
        )
    lines.append("")

    path.write_text("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kavach eval harness")
    ap.add_argument("--dataset", default=str(ROOT / "eval" / "dataset.jsonl"))
    ap.add_argument("--outdir", default=str(ROOT / "eval"))
    ap.add_argument("--limit", type=int, default=None, help="Only evaluate the first N rows")
    ap.add_argument("--delay", type=float, default=1.5, help="Seconds between calls (rate-limit safety)")
    ap.add_argument("--risk-threshold", type=int, default=40, help="risk >= threshold => predicted_is_scam=True")
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

    # Read the model in use for the report.
    try:
        from core.config import settings as _settings

        model_used = _settings.model
    except Exception:
        model_used = "unknown"

    config = {
        "dataset": str(dataset_path),
        "limit": args.limit,
        "delay": args.delay,
        "risk_threshold": args.risk_threshold,
        "model": model_used,
    }

    print(f"# Kavach eval — {len(rows)} rows, delay={args.delay}s, threshold={args.risk_threshold}")
    print(f"# Model: {model_used}")

    try:
        results = evaluate(rows, delay=args.delay, risk_threshold=args.risk_threshold)
    except KeyboardInterrupt:
        print("\nInterrupted. Writing partial results...", file=sys.stderr)
        return 130

    metrics = compute_metrics(results)
    write_results_json(results, metrics, config, outdir / "results.json")
    write_report_md(metrics, config, outdir / "report.md")

    b = metrics["binary"]
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Rows: {metrics['total']}   OK: {metrics['ok']}   Errors: {metrics['errors']}")
    print(f"scam_type accuracy : {_fmt_pct(metrics['scam_type_accuracy'])}")
    print(f"Binary   precision : {b['precision']:.3f}")
    print(f"Binary   recall    : {b['recall']:.3f}")
    print(f"Binary   F1        : {b['f1']:.3f}")
    print(f"False positive rate: {_fmt_pct(b['false_positive_rate'])}")
    print(f"False negative rate: {_fmt_pct(b['false_negative_rate'])}")
    print(f"Latency mean/p95   : {metrics['latency']['mean']}s / {metrics['latency']['p95']}s")
    print(f"Coverage           : {metrics['coverage']}")
    print()
    print(f"Wrote: {outdir / 'report.md'}")
    print(f"Wrote: {outdir / 'results.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
