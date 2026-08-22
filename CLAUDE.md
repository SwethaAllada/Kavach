## Project
Kavach — scam/fraud detection for Indian citizens. FastAPI backend, React/Vite frontend,
Grok via OpenAI-compatible SDK, Supabase (5 anonymized fields only, message content NEVER
persisted), Twilio WhatsApp, Render + Vercel.
Engine is hybrid: deterministic rules + LLM reasoning + lexical RAG.
There is NO trained model — reliability comes from rules, the RAG KB, and the prompt.

## Hard constraints (finale in 2 days)
- 52 tests pass today. They must pass after every change. Run them and report the count.
- ADDITIVE ONLY. Do not move, rename, or delete existing modules.
- Never persist message content. Five anonymized fields is the ceiling.
- Ask before committing. Never force-push.
- If a change needs >30 min or touches >5 files, STOP and propose first.