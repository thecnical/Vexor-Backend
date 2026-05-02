"""
Vexor Backend — FastAPI
AI Router + Auth + API
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.database.db import init_db
from app.auth.router import router as auth_router
from app.ai.router import router as ai_router
from app.api.scan import router as scan_router
from app.api.osint import router as osint_router
from app.api.sync import router as sync_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="Vexor Backend",
    description="AI-Powered Security Toolkit Backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/v1/auth",  tags=["auth"])
app.include_router(ai_router,   prefix="/api/v1/ai",    tags=["ai"])
app.include_router(scan_router, prefix="/api/v1/scan",  tags=["scan"])
app.include_router(osint_router,prefix="/api/v1/osint", tags=["osint"])
app.include_router(sync_router, prefix="/api/v1/sync",  tags=["sync"])


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "service": "vexor-backend", "version": "1.0.0"}
