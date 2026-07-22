import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    def __init__(self):
        self.xai_api_key: str = os.getenv("XAI_API_KEY", "")
        self.supabase_url: str = os.getenv("SUPABASE_URL", "")
        self.supabase_service_key: str = os.getenv("SUPABASE_SERVICE_KEY", "")
        self.twilio_auth_token: str = os.getenv("TWILIO_AUTH_TOKEN", "")
        # Off by default for local dev; flip to "true" in production once the
        # webhook is reachable from Twilio and the token is set.
        self.verify_twilio_signature: bool = os.getenv(
            "VERIFY_TWILIO_SIGNATURE", "false"
        ).strip().lower() in ("1", "true", "yes", "on")
        self.frontend_origin: str = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")

        self.model: str = os.getenv("KAVACH_MODEL", "grok-3-mini")
        self.base_url: str = os.getenv("KAVACH_BASE_URL", "https://api.x.ai/v1")
        self.llm_timeout_s: int = int(os.getenv("KAVACH_LLM_TIMEOUT_S", "20"))
        self.max_retries: int = int(os.getenv("KAVACH_MAX_RETRIES", "2"))


settings = Settings()
