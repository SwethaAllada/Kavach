# Kavach

Citizen fraud-detection assistant (web + WhatsApp, LLM-powered). Phase 0: scaffold only —
all analysis logic is stubbed.

## Backend setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend runs on http://localhost:8000.

## Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on http://localhost:5173.

## Environment variables

Copy `.env.example` to `.env` in the project root and fill in values as needed:

```bash
cp .env.example .env
```

No API key is required to run the Phase 0 stub — `/analyze` returns a hardcoded response.

## Multi-channel architecture

Kavach is built around a single decision engine (`backend/services/classifier.py`) that
every channel shares. Adding a new channel is a thin adapter, not a new AI system.

- **Web** — live. `POST /analyze` returns the full Verdict JSON, rendered by the React
  frontend (`frontend/src/`).
- **WhatsApp** — adapter ready. `POST /webhook` accepts Twilio's form-encoded inbound
  message, calls the same `analyze()` used by `/analyze`, and returns a TwiML reply.
  Language is auto-detected and the reply is written in the user's language.
  Signature verification is toggleable via `VERIFY_TWILIO_SIGNATURE` (off by default for
  local testing, flip to `true` in production). See `backend/routes/webhook.py`.
- **IVR / mobile / any future channel** — same pattern: parse the inbound payload, call
  `analyze(text)`, format the returned Verdict for the channel. No engine changes needed.

## Evaluation harness

Runs the same `analyze()` the API uses against a labeled dataset and reports accuracy / precision / recall / F1 / false-positive rate / false-negative rate, per-class metrics, latency, and coverage.

From the project root (`kavach/`), with the backend venv active and `XAI_API_KEY` in `.env`:

```bash
# Smoke test (10 rows, 1.5s pause between calls to be nice to the LLM).
python eval/run_eval.py --limit 10 --delay 1.5

# Full run on the whole dataset.
python eval/run_eval.py --delay 1.5

# Optional flags
#   --dataset PATH       default: eval/dataset.jsonl
#   --outdir DIR         default: eval/
#   --limit N            only evaluate the first N rows
#   --delay SECONDS      pause between LLM calls (default 1.5s)
#   --risk-threshold N   risk >= N => classifier "predicts scam" (default 40)
```

Outputs land in `eval/`:
- `eval/report.md` — human-readable tables (headline, confusion, per-class, latency, coverage, by language).
- `eval/results.json` — every per-row prediction, plus config + metrics, for auditability.

## Project structure

- `backend/` — FastAPI service (routes, services, core config, Pydantic schemas)
- `frontend/` — React + Vite web client
- `data/` — scam knowledge base (empty, filled in later phases)
- `eval/` — evaluation harness and dataset (stub, filled in later phases)
- `docs/` — architecture, security, privacy, business, and demo notes
- `deploy/` — Render and Vercel deployment configs
