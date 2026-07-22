# Kavach — Evaluation Report

**Generated:** 2026-07-21T17:40:06.071836Z

## Config

| Setting | Value |
| --- | --- |
| Dataset | `/Users/allada.swethaditya/Personal/Kavach/kavach/eval/dataset.jsonl` |
| Rows evaluated | 110 |
| Successful predictions | 110 |
| Errors | 0 |
| Risk threshold (is_scam gate) | `risk >= 40` |
| Delay between calls | 1.5s |
| Limit | none (full run) |
| Model | grok-3-mini |

## Headline

- **Scam-type exact accuracy:** 99.1% (109/110)
- **Binary scam vs. legit F1:** 1.000 — precision 1.000, recall 1.000
- **False positive rate** (legit flagged as scam): 0.0% (0 of 35 legit)
- **False negative rate** (scams missed): 0.0% (0 of 75 scams)

## Confusion Summary

| Bucket | Count |
| --- | ---: |
| Correct scam type | 109 |
| Caught as scam but wrong type | 1 |
| Missed scams (false negatives) | 0 |
| False alarms (legit flagged) | 0 |

## Binary Classifier Metrics

| Metric | Value |
| --- | ---: |
| True positives | 75 |
| False positives | 0 |
| True negatives | 35 |
| False negatives | 0 |
| Precision | 1.000 |
| Recall | 1.000 |
| F1 | 1.000 |
| False positive rate | 0.0% |
| False negative rate | 0.0% |

## Per-Class Metrics (scam_type)

| Class | Support | TP | FP | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| courier_parcel | 7 | 6 | 0 | 1 | 1.000 | 0.857 | 0.923 |
| deepfake_voice | 4 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| digital_arrest | 9 | 9 | 1 | 0 | 0.900 | 1.000 | 0.947 |
| investment_stock | 9 | 9 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| job_task | 7 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| kyc_bank | 11 | 11 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| likely_safe | 35 | 35 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| loan_app | 6 | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| lottery_prize | 7 | 7 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| romance | 4 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| tech_support | 5 | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| upi_collect_request | 6 | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |

## Latency (seconds)

| Stat | Value |
| --- | ---: |
| n | 110 |
| Mean | 6.544 |
| Median | 6.049 |
| p95 | 11.213 |
| Min | 3.522 |
| Max | 14.693 |

## Coverage (decision source)

| Source | Count |
| --- | ---: |
| rules+llm+rag | 75 |
| rules+llm | 35 |

## By Language

| Language | Rows | Type accuracy | Binary accuracy |
| --- | ---: | ---: | ---: |
| en | 84 | 98.8% | 100.0% |
| hi | 14 | 100.0% | 100.0% |
| te | 12 | 100.0% | 100.0% |
