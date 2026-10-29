from fastapi import FastAPI
from app.core.config import settings
from app.db.init_db import init_db
from app.api.routes import assets, audits, drift

app = FastAPI(title=settings.app_name, version="0.1.0")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/")
def root():
    return {"message": settings.app_name, "docs": "/docs"}


@app.get("/api/health")
def health():
    return {"status": "ok"}


app.include_router(assets.router, prefix=settings.api_prefix)
app.include_router(audits.router, prefix=settings.api_prefix)
app.include_router(drift.router, prefix=settings.api_prefix)
