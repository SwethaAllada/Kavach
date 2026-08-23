# Kavach

A citizen-safety tool that checks any suspicious call, SMS, or WhatsApp message before you act.
Built for the Indian scam landscape: digital-arrest calls, fake KYC, courier-parcel customs,
guaranteed-return investment groups, and 8 more scam categories, in **English, Hindi, and Telugu**.

**Live demo:**

- Web: <https://kavach-blue.vercel.app>
- Backend health: <https://kavach-backend-lt44.onrender.com/health>
- Live trends aggregate: <https://kavach-backend-lt44.onrender.com/trends>


---

## What it does

1. Paste a suspicious message into the web UI (or forward it to the WhatsApp number).
2. In ~7 seconds, Kavach returns a **Verdict**:
   - Risk score (0–100) and scam category
   - Detected language, with the explanation and recommended action written in that language
   - Warning signals detected (authority impersonation, fear/threats, isolation, payment demand, …)
   - **Citations** — pattern IDs from the knowledge base that matched your message, with the
     exact matched phrases, so you can see *why* it decided what it did
   - A ready-to-file complaint description, tap-to-call links for 1930, evidence checklist —
     but *only* if the message is actually a scam (no complaint push on legit OTPs)
3. Anonymized-only telemetry (scam type, risk bucket, language) writes to Supabase for the
   live Trends dashboard. **Message text never leaves the request path.**

## Architecture — one engine, many doorways

Kavach is a single decision engine ([`backend/services/classifier.py`](backend/services/classifier.py))
with thin, channel-specific adapters. Adding a new channel is not a new AI system.

```
                                                            ┌──────────────────┐
Web UI (Vercel) ──► POST /analyze  ──┐                 ┌──►│ xAI Grok LLM     │
                                     │                 │   └──────────────────┘
Twilio inbound ───► POST /webhook ───┼──► analyze() ───┼──► rules_classify (regex, 3-lang)
                                     │                 │
IVR (planned) ────► same call    ───┘                 └──► rag.retrieve (KB citations)
                                                            │
                                                            ▼
                                                        Verdict → guided report
                                                        Anonymized telemetry → Supabase
```

- **Rules layer** — deterministic regex classifier over a 12-scam-type taxonomy, in EN/HI/TE.
  Runs first, always, in <1ms. Never raises.
- **LLM layer** — xAI Grok (`grok-3-mini`) via OpenAI-compatible SDK. Wrapped with a
  prompt-injection guard (user message wrapped in `<user_message>` tags; system prompt tells
  the model to treat everything inside as data, not instructions). Strict JSON output validated
  against the taxonomy.
- **RAG layer** — lightweight lexical retriever ([`backend/services/rag.py`](backend/services/rag.py))
  over a 22-entry multilingual scam knowledge base ([`data/scam_kb.json`](data/scam_kb.json)).
  Returns matched patterns as citations. Advisory only — the "safe-lock" prevents RAG from
  flipping a confident `likely_safe` verdict, so it can't cause false positives.
- **Fallback** — if the LLM is unavailable (timeout, 4xx, network), the engine returns a
  full valid Verdict from the rules layer alone. `/analyze` never returns 500.
- **Anonymized telemetry** — a five-field whitelist enforced in code
  ([`backend/core/privacy.py`](backend/core/privacy.py)) writes only `scam_type`, `risk_bucket`,
  `detected_language`, `decision_source`, `fallback_used` to Supabase. Fire-and-forget; a
  telemetry outage cannot affect the user-facing response.

Full multi-channel discussion below; full privacy/security discussion in [`docs/`](docs/).

## Local setup

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn main:app --port 8000 --reload
```

Backend runs on <http://localhost:8000>. Test with `curl http://localhost:8000/health`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on <http://localhost:5173>. It expects the backend at
`http://localhost:8000` (override with `VITE_API_BASE` in `frontend/.env.local`).

### Environment variables

Copy `.env.example` to `.env` in the project root and fill in the values you have:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|:---:|---|
| `XAI_API_KEY` | ✅ | xAI Grok API key (`xai-…`). Backend-only. Get one at <https://console.x.ai>. |
| `SUPABASE_URL` | for /trends | Your Supabase project URL. Backend-only. |
| `SUPABASE_SERVICE_KEY` | for /trends | Supabase **service_role** key (never anon). Backend-only. |
| `TWILIO_AUTH_TOKEN` | for WhatsApp | Twilio auth token. Backend-only. Leave blank until you connect a number. |
| `VERIFY_TWILIO_SIGNATURE` | | `true` in production, blank/`false` locally. |
| `FRONTEND_ORIGIN` | | CORS allowlist, comma-separated. Defaults to `http://localhost:5173`. |
| `KAVACH_RATE_LIMIT_PER_MIN` | | Per-IP rate limit on `/analyze` and `/webhook`. Default 30. |
| `KAVACH_RATE_LIMIT_ENABLED` | | `false` to disable rate limiting (local load testing only). |
| `KAVACH_MODEL` | | Overrides the default `grok-3-mini`. |
| `KAVACH_BASE_URL` | | Overrides the default `https://api.x.ai/v1`. |

**Without any keys**, the backend still starts. `/analyze` returns a valid Verdict from the
rules-only fallback path, `/trends` returns `{"status":"unavailable", ...}`, and the frontend
renders correctly. So you can clone → `npm run dev` → click a chip → see the fallback path
work, without any API accounts.

### Supabase table (only if you want /trends)

Run the DDL in [`deploy/supabase.sql`](deploy/supabase.sql) once in the Supabase SQL editor.
That creates the `signals` table with exactly the six whitelisted columns — no free-form
`payload` / `metadata` / `raw_text` columns exist, so message text is structurally impossible
to leak. See [`docs/privacy.md`](docs/privacy.md).

## Multi-channel architecture

Kavach is built around a single decision engine that every channel shares.

- **Web** — live. `POST /analyze` returns the full Verdict JSON, rendered by the React
  frontend at `frontend/src/`.
- **WhatsApp** — adapter ready. `POST /webhook` accepts Twilio's form-encoded inbound message,
  calls the same `analyze()` used by `/analyze`, and returns a TwiML reply written in the
  detected language. Signature verification is HMAC-SHA1 against `TWILIO_AUTH_TOKEN`,
  toggleable via `VERIFY_TWILIO_SIGNATURE`. See
  [`backend/routes/webhook.py`](backend/routes/webhook.py) — 154 lines total.
- **IVR / mobile / any future channel** — same three-step pattern: parse the inbound payload,
  call `analyze(text)`, format the returned Verdict for the channel. No engine changes needed.

## Evaluation harness

Runs the same `analyze()` the API uses against a labeled dataset and reports
accuracy / precision / recall / F1 / false-positive rate / false-negative rate,
per-class metrics, latency, and coverage. From the project root, with the backend venv active
and `XAI_API_KEY` in `.env`:

```bash
# Smoke test (10 rows, 1.5s pause between calls to be nice to the LLM).
python eval/run_eval.py --limit 10 --delay 1.5

# Full run on the whole dataset (~15 min for 110 rows).
python eval/run_eval.py --delay 1.5

# Optional flags
#   --dataset PATH       default: eval/dataset.jsonl
#   --outdir DIR         default: eval/
#   --limit N            only evaluate the first N rows
#   --delay SECONDS      pause between LLM calls (default 1.5s)
#   --risk-threshold N   risk >= N => classifier "predicts scam" (default 40)
```

Outputs land in `eval/`:

- `eval/report.md` — human-readable tables (headline, confusion, per-class, latency,
  coverage, by language).
- `eval/results.json` — every per-row prediction, plus config + metrics, for auditability.

Latest headline (110 rows, 25 legit + 85 scam across all 11 scam types × 3 languages):

- **Scam-type accuracy: 99.1%** (109/110)
- **Binary F1: 1.000** (precision 1.000, recall 1.000)
- **False-positive rate: 0.0%** (0/25 legit messages flagged)
- **False-negative rate: 0.0%** (0/85 scams missed)

## Tests

**52 tests, all passing.**

```bash
cd backend
./venv/bin/python -m pytest tests/ -v
```

Coverage highlights:

- Engine correctness (English + Hindi + Telugu scams; legit OTP not over-flagged; LLM fallback)
- RAG grounding (retrieval hits real patterns; safe-lock prevents flipping `likely_safe`)
- Guided reporting (paste-ready complaint summary in the detected language; no push on legit)
- Anonymized telemetry (whitelist enforced; telemetry failure cannot affect `/analyze`;
  byte-identity regression with telemetry on vs off)
- WhatsApp adapter (TwiML shape, char limit, signature verification toggle, engine-reuse
  agreement between `/webhook` and `/analyze`)
- Security (rate limiter 429 behavior, per-IP isolation, fail-open on bug; CORS allowlist
  correct for allowed/disallowed origins; security headers on every response)

## Project structure

```
backend/            FastAPI service
  main.py             CORS + rate-limit + security-headers middleware + router mounts
  core/
    config.py         env-var loading; typed settings
    privacy.py        anonymization whitelist for telemetry
    rate_limit.py     per-IP sliding-window rate limiter (dep-free)
  services/
    classifier.py     the hybrid decision engine — rules + LLM + RAG + report + telemetry
    rules.py          deterministic regex classifier (EN/HI/TE)
    llm.py            xAI Grok call with prompt-injection guard, retries, defensive parsing
    rag.py            lexical retriever over data/scam_kb.json
    report.py         guided-reporting package builder (paste-ready complaint + evidence)
    store.py          Supabase telemetry writer (fire-and-forget) + trends aggregator
    whatsapp_format.py  Verdict → WhatsApp-friendly plain-text formatter (EN/HI/TE)
  routes/
    analyze.py        POST /analyze
    trends.py         GET  /trends
    webhook.py        POST /webhook (Twilio TwiML)
  models/schemas.py   Pydantic response schema
  tests/              52 tests
frontend/           React + Vite web client
  src/
    App.jsx           layout, Analyze/Trends tabs
    components/       AnalyzePanel, VerdictCard, RiskMeter, SignalChips,
                      ReportLinks, TrendsDashboard
    lib/api.js        typed API client with graceful error handling
    styles/index.css  design system (trust-blue palette, semantic risk colors,
                      reduced-motion, mobile-responsive)
data/kb/*.yaml      source-of-truth KB entries, one file per entry
data/scam_kb.json   22-entry multilingual scam knowledge base — a BUILD ARTIFACT of
                    data/kb/*.yaml. Regenerate with `python scripts/build_kb.py` after
                    editing any data/kb/*.yaml file (`--check` verifies it's up to date
                    without writing — editing a .yaml and forgetting to rebuild would
                    otherwise leave rag.py silently serving stale content).
locales/            per-language response strings (locales/<code>/responses.yaml),
                    the source of truth for classifier.py/report.py/whatsapp_format.py
                    reply text, read via backend/core/locales_loader.py
eval/               110-row labeled dataset + evaluation harness
deploy/             render.yaml, vercel.json, supabase.sql
docs/               privacy.md, security.md, architecture.md, business.md, demo-script.md
```

## Deployment

- **Backend → Render.** [`deploy/render.yaml`](deploy/render.yaml) blueprint auto-provisions
  the service. Paste the env vars listed above into the Render dashboard.
- **Frontend → Vercel.** Root directory `frontend/`, framework auto-detects Vite. Set one
  env var: `VITE_API_BASE` = your Render URL (no trailing slash).
- **Supabase.** Paste [`deploy/supabase.sql`](deploy/supabase.sql) into the SQL editor.
- **CORS handshake.** Once the Vercel URL is minted, set `FRONTEND_ORIGIN` on Render to
  that exact URL and redeploy. This is a one-time chicken-and-egg step.

Free tiers on both platforms are enough for demos; Render's free tier sleeps after ~15 min
of idle, so the first request after idle takes ~30–50s (cold-start). Every request after
that is normal.

## Security & privacy

See [`docs/security.md`](docs/security.md) and [`docs/privacy.md`](docs/privacy.md).

TL;DR:

- All provider secrets (`XAI_API_KEY`, `SUPABASE_SERVICE_KEY`, `TWILIO_AUTH_TOKEN`) are
  backend-only. Vite structurally cannot bundle non-`VITE_*` env vars into the client.
- Anonymized telemetry only. The `signals` table has six columns; there is no schema slot
  for message text. Aligned with DPDP Act §4 / §5 / §8(3).
- User messages are treated as **data, not instructions** — prompt-injection guard on the
  LLM call ([`backend/services/llm.py`](backend/services/llm.py)).
- CORS locked to `FRONTEND_ORIGIN`; per-IP sliding-window rate limiter; security headers
  (`nosniff`, `Referrer-Policy`, `Cache-Control: no-store`, `X-Frame-Options: DENY`) on
  every response.
- Twilio webhook signature verification (HMAC-SHA1) toggleable via
  `VERIFY_TWILIO_SIGNATURE`.
- Honest limitations documented in `docs/security.md` § Known Limitations (in-memory rate
  limiter doesn't work well behind multi-worker deployments; move to Redis or Cloudflare
  edge before real production traffic).

## Reporting scope

Kavach is **guidance only.** It never files reports on the user's behalf — it prepares a
paste-ready complaint description in the user's language and links them to the official
Indian reporting channels (Cyber Crime Helpline **1930**, <https://cybercrime.gov.in>,
<https://sancharsaathi.gov.in/sfc/>). The user files the actual complaint. This is a
deliberate design choice: auto-filing would be legally risky and there is no public API
for it.
