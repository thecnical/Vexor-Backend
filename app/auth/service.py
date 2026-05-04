"""
Vexor Auth Service
- Fixed: datetime.utcnow() replaced with timezone-aware datetime (Python 3.12+)
- Fixed: Insecure SECRET_KEY now raises RuntimeError in production
- Added: JWT token revocation (blacklist) support
- Added: JTI claim for per-token revocation
"""
import os
import sys
import pathlib
import uuid
import warnings
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
import aiosqlite

from app.database.db import DB_PATH

# ─── Security Config ─────────────────────────────────────────────────────────

_raw_secret = os.getenv("SECRET_KEY", "")
_is_production = os.getenv("VEXOR_ENV", "development").lower() == "production"

if not _raw_secret:
    if _is_production:
        raise RuntimeError(
            "FATAL: SECRET_KEY environment variable is not set. "
            "In production this is a critical security risk. "
            "Set SECRET_KEY to a cryptographically random 256-bit string."
        )
    else:
        warnings.warn(
            "SECRET_KEY env var not set — using insecure default for development. "
            "Set SECRET_KEY=<random-256-bit-string> before deploying to production.",
            RuntimeWarning,
            stacklevel=1,
        )
        _raw_secret = "vexor-dev-insecure-secret-NEVER-USE-IN-PRODUCTION-aa7b3c9d"

SECRET_KEY = _raw_secret
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 60 * 24   # 24 hours
REFRESH_TOKEN_EXPIRE_DAYS    = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


# ─── Auth Service ────────────────────────────────────────────────────────────

class AuthService:

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    def _create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        to_encode.update({
            "exp":  datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            "iat":  datetime.now(timezone.utc),
            "type": "access",
            "jti":  uuid.uuid4().hex,   # unique per-token ID for revocation
        })
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    def _create_refresh_token(self, data: dict) -> str:
        to_encode = data.copy()
        to_encode.update({
            "exp":  datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
            "iat":  datetime.now(timezone.utc),
            "type": "refresh",
            "jti":  uuid.uuid4().hex,
        })
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    async def register(self, email: str, password: str, username: str) -> Optional[dict]:
        hashed = self._hash_password(password)
        async with aiosqlite.connect(DB_PATH) as db:
            try:
                await db.execute(
                    "INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)",
                    (email, username, hashed)
                )
                await db.commit()
                return {"email": email, "username": username}
            except Exception:
                return None

    async def login(self, email: str, password: str) -> Optional[dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT id, email, username, password_hash FROM users WHERE email = ?",
                (email,)
            ) as cursor:
                row = await cursor.fetchone()
        if not row:
            return None
        user_id, user_email, username, password_hash = row
        if not self._verify_password(password, password_hash):
            return None
        access  = self._create_access_token({"sub": str(user_id), "email": user_email})
        refresh = self._create_refresh_token({"sub": str(user_id), "email": user_email})
        return {
            "access_token":  access,
            "refresh_token": refresh,
            "token_type":    "bearer",
            "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {"id": user_id, "email": user_email, "username": username},
        }

    async def refresh(self, refresh_token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type") != "refresh":
                return None
            user_id = payload.get("sub")
            email   = payload.get("email")
            jti     = payload.get("jti", "")
            if not user_id:
                return None

            # Check if token is revoked
            if await self._is_revoked(jti):
                return None

            new_access = self._create_access_token({"sub": user_id, "email": email})
            return {
                "access_token": new_access,
                "token_type":   "bearer",
                "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            }
        except JWTError:
            return None

    async def logout(self, token: str) -> bool:
        """Revoke a token (access or refresh) by adding its JTI to the blacklist."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti", "")
            if not jti:
                return False
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "INSERT OR IGNORE INTO revoked_tokens (jti) VALUES (?)", (jti,)
                )
                await db.commit()
            return True
        except JWTError:
            return False

    async def _is_revoked(self, jti: str) -> bool:
        if not jti:
            return False
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)
            ) as cursor:
                return (await cursor.fetchone()) is not None
