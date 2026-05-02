"""
Vexor Backend — FastAPI v4.0.0
AI Router + Auth + OSINT + Cloud Sync + Team Collaboration
"""
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import time
from collections import defaultdict

from app.database.db import init_db
from app.auth.router import router as auth_router
from app.ai.router import router as ai_router
from app.api.scan import router as scan_router
from app.api.osint import router as osint_router
from app.api.sync import router as sync_router


# ─── Rate limiting (simple in-memory) ────────────────────────────────────────
_rate_limit_store: dict = defaultdict(list)
RATE_LIMIT_REQUESTS = 100   # requests per window
RATE_LIMIT_WINDOW   = 60    # seconds


def _is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    requests = _rate_limit_store[client_ip]
    # Remove old requests outside window
    _rate_limit_store[client_ip] = [t for t in requests if t > window_start]
    if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return True
    _rate_limit_store[client_ip].append(now)
    return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="Vexor Backend",
    description="AI-Powered Security Toolkit Backend — v4.0.0",
    version="4.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ─── CORS — restrict to known origins ────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "https://vexor.vercel.app,https://vexor.io,http://localhost:3000,http://localhost:8000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)


# ─── Rate limiting middleware ─────────────────────────────────────────────────
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Skip rate limiting for health check
    if request.url.path == "/api/v1/health":
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    if _is_rate_limited(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again in 60 seconds."},
        )
    return await call_next(request)


# ─── Security headers middleware ──────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth_router, prefix="/api/v1/auth",  tags=["auth"])
app.include_router(ai_router,   prefix="/api/v1/ai",    tags=["ai"])
app.include_router(scan_router, prefix="/api/v1/scan",  tags=["scan"])
app.include_router(osint_router,prefix="/api/v1/osint", tags=["osint"])
app.include_router(sync_router, prefix="/api/v1/sync",  tags=["sync"])


@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "service": "vexor-backend",
        "version": "4.0.0",
    }


@app.get("/")
async def root():
    return {
        "service": "Vexor Backend",
        "version": "4.0.0",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
