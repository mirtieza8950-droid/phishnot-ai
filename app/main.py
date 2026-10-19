import os
from pathlib import Path

# ── Redirect all model/dataset caches (cross-platform) ────────────────────────
_CACHE = os.environ.get("HF_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "phishnot"))
os.makedirs(os.path.join(_CACHE, "hub"), exist_ok=True)
os.makedirs(os.path.join(_CACHE, "torch"), exist_ok=True)
os.environ.setdefault("HF_HOME",            os.environ.get("HF_HOME", _CACHE))
os.environ.setdefault("HF_HUB_CACHE",       os.path.join(_CACHE, "hub"))
os.environ.setdefault("TRANSFORMERS_CACHE", os.path.join(_CACHE, "hub"))
os.environ.setdefault("TORCH_HOME",         os.path.join(_CACHE, "torch"))
# ─────────────────────────────────────────────────────────────────────────────

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.limiter import limiter   # F-45: shared instance

from app.core.config import settings
from app.api.v1.router import api_router
from app.api.v1.auth import router as auth_router

# Production frontend path (built by `cd frontend && npm run build`)
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")

app = FastAPI(title="Phishnot AI", version="5.0")

# ── Rate limiter (shared instance) ────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── CORS - F-28: origins from env var; explicit methods/headers ───────────────
_raw_origins = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
)
_allowed_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
    allow_credentials=True,
)

# ── Session middleware ─────────────────────
app.add_middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)

# ── Secure headers ─────────────────────────
class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response
app.add_middleware(SecureHeadersMiddleware)

# ── Include routers ────────────────────────
app.include_router(api_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])

# ── Startup ────────────────────────────────
_DEFAULT_ADMIN_PW = "phishguard2025"
_DEFAULT_SESSION_SECRET = "replace-me-with-a-random-secret"

@app.on_event("startup")
def startup():
    import logging, threading
    logger = logging.getLogger("phishguard.startup")

    # Warn loudly if insecure defaults are still in use
    if settings.ADMIN_PASSWORD == _DEFAULT_ADMIN_PW:
        logger.warning(
            "SECURITY WARNING: ADMIN_PASSWORD is still the default value. "
            "Set a strong password in your .env file before exposing this service."
        )
    if settings.SESSION_SECRET == _DEFAULT_SESSION_SECRET:
        logger.warning(
            "SECURITY WARNING: SESSION_SECRET is still the default value. "
            "Set a random 32-byte secret in your .env file."
        )

    from app.services.ensemble_engine import load_all_models
    load_all_models()

    # Mark models as ready after successful load
    app.state.models_ready = True

    from app.services.ai_chat import init_ai_client
    init_ai_client()
    from app.services.scan_processor import reload_whitelist
    reload_whitelist()
    from app.services.url_reputation import init_tranco
    threading.Thread(target=init_tranco, daemon=True).start()
    # Vision model loads lazily on first use — no GPU at startup

    # Start self-learning scheduler (weekly meta-learner, monthly LoRA)
    try:
        from app.services.self_learning_scheduler import start_scheduler
        start_scheduler()
    except Exception as e:
        logger.warning(f"Self-learning scheduler failed to start: {e}")



@app.on_event("shutdown")
def shutdown():
    try:
        from app.services.self_learning_scheduler import stop_scheduler
        stop_scheduler()
    except Exception:
        pass


# ── Health / Status ────────────────────────
@app.get("/health")
def health():
    ready = getattr(app.state, "models_ready", False)
    if not ready:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            {"status": "starting", "models_ready": False, "version": "5.0"},
            status_code=503,
        )
    return {"status": "ok", "models_ready": True, "version": "5.0"}

@app.get("/api/v1/status")
def status():
    return {"message": "PhishGuard AI API", "docs": "/docs"}

# ── Serve built Vite frontend for production ──
if os.path.isdir(FRONTEND_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def serve_spa(full_path: str):
        index = os.path.join(FRONTEND_DIST, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
        return JSONResponse({"detail": "Frontend not built. Run: cd frontend && npm run build"}, status_code=404)
else:
    @app.get("/")
    def root():
        return {"message": "PhishGuard AI API v5.0", "docs": "/docs",
                "note": "Frontend dev server: cd frontend && npm run dev"}