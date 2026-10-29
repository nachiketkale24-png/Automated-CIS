import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import settings
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.api.routes import assets, audits, drift, run_audit

logger = logging.getLogger(__name__)


# ── Lifespan (replaces deprecated @app.on_event) ─────────────────────
@asynccontextmanager
async def lifespan(application: FastAPI):
    # Startup
    init_db()
    logger.info("Database tables verified / created.")
    yield
    # Shutdown (cleanup if needed later)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

# ── CORS for Shristi's React frontend ────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Root / health ────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"message": settings.app_name, "docs": "/docs"}


@app.get("/api/health")
def health():
    """Report application and database connectivity."""
    db_ok = False
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db_ok = True
        db.close()
    except Exception as exc:
        logger.error("Health-check DB probe failed: %s", exc)

    status = "healthy" if db_ok else "degraded"
    return {
        "status": status,
        "database": "connected" if db_ok else "unavailable",
        "app": settings.app_name,
    }


# ── Routers ──────────────────────────────────────────────────────────
app.include_router(assets.router, prefix=settings.api_prefix)
app.include_router(audits.router, prefix=settings.api_prefix)
app.include_router(drift.router, prefix=settings.api_prefix)
app.include_router(run_audit.router, prefix=settings.api_prefix)
