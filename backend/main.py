from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from routes import analyze, trends, webhook

app = FastAPI(title="Kavach API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin, "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router)
app.include_router(webhook.router)
app.include_router(trends.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
