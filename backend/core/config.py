import os

from dotenv import load_dotenv

load_dotenv()


def _parse_origins(raw: str) -> list[str]:
    """Split a comma-separated FRONTEND_ORIGIN into a clean allowlist.

    Whitespace, empty entries, and trailing slashes are normalized away so
    small env-var typos don't quietly reject a legit origin.
    """
    if not raw:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for piece in raw.split(","):
        origin = piece.strip().rstrip("/")
        if origin and origin not in seen:
            seen.add(origin)
            out.append(origin)
    return out


def _parse_bool(raw: str, default: bool = False) -> bool:
    return (raw or "").strip().lower() in ("1", "true", "yes", "on") if raw else default


def _parse_int(raw: str, default: int) -> int:
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


class Settings:
    def __init__(self):
        # --- Secrets (backend-only, never exposed to frontend) ------------------
        self.xai_api_key: str = os.getenv("XAI_API_KEY", "")
        self.supabase_url: str = os.getenv("SUPABASE_URL", "")
        self.supabase_service_key: str = os.getenv("SUPABASE_SERVICE_KEY", "")
        self.twilio_account_sid: str = os.getenv("TWILIO_ACCOUNT_SID", "")
        self.twilio_auth_token: str = os.getenv("TWILIO_AUTH_TOKEN", "")

        # --- CORS ---------------------------------------------------------------
        # `FRONTEND_ORIGIN` accepts one origin OR a comma-separated list. In
        # production this is the Vercel URL (or several if you run staging).
        # Default is localhost:5173 for local dev.
        raw_origins = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
        self.allowed_origins: list[str] = _parse_origins(raw_origins) or ["http://localhost:5173"]
        # Backwards-compat single-string accessor for older imports.
        self.frontend_origin: str = self.allowed_origins[0]

        # --- Twilio webhook signature verification ------------------------------
        # Off by default for local dev; flip to "true" in production once the
        # webhook is reachable from Twilio and the token is set.
        self.verify_twilio_signature: bool = _parse_bool(
            os.getenv("VERIFY_TWILIO_SIGNATURE", "false"), default=False
        )

        # --- Rate limiting ------------------------------------------------------
        # Per-IP sliding window. Applies to /analyze and /webhook.
        self.rate_limit_per_min: int = _parse_int(
            os.getenv("KAVACH_RATE_LIMIT_PER_MIN", "30"), default=30
        )
        self.rate_limit_enabled: bool = _parse_bool(
            os.getenv("KAVACH_RATE_LIMIT_ENABLED", "true"), default=True
        )

        # --- LLM ----------------------------------------------------------------
        self.model: str = os.getenv("KAVACH_MODEL", "grok-3-mini")
        self.base_url: str = os.getenv("KAVACH_BASE_URL", "https://api.x.ai/v1")
        self.llm_timeout_s: int = _parse_int(os.getenv("KAVACH_LLM_TIMEOUT_S", "20"), 20)
        self.max_retries: int = _parse_int(os.getenv("KAVACH_MAX_RETRIES", "2"), 2)

        # --- Vision (screenshot text extraction, services/vision.py) ------------
        # A separate, explicitly-named model so a vision-capable model is never
        # silently swapped for the text model (or vice versa) by editing one
        # shared setting. grok-4.6 supports image input natively.
        self.vision_model: str = os.getenv("KAVACH_VISION_MODEL", "grok-4.6")

        # --- Translation (locales_loader.py) -------------------------------------
        # Runtime translation via deep-translator for languages with no
        # authored locales/<code>/ YAML. On by default; tests set this False
        # (settings.translation_enabled = False) so the suite never makes a
        # real network call to Google Translate.
        self.translation_enabled: bool = _parse_bool(
            os.getenv("KAVACH_TRANSLATION_ENABLED", "true"), default=True
        )


settings = Settings()
