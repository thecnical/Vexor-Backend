"""
Vexor Auth Service
"""
import os
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from jose import jwt
from app.database.db import get_db
import aiosqlite

SECRET_KEY = os.getenv("SECRET_KEY", "vexor-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:

    def _hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def _verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    def _create_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        to_encode["exp"] = expire
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    async def register(self, email: str, password: str, username: str) -> Optional[dict]:
        hashed = self._hash_password(password)
        async with aiosqlite.connect("vexor.db") as db:
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
        async with aiosqlite.connect("vexor.db") as db:
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

        token = self._create_token({"sub": str(user_id), "email": user_email})
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": {"id": user_id, "email": user_email, "username": username},
        }
