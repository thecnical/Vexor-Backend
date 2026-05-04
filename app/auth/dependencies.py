"""
JWT Auth Dependencies
- Fixed: SECRET_KEY sourced from shared auth service (not re-declared here)
- Fixed: Revoked token check on every request
- Added: User object includes username from DB
"""
from datetime import timezone
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from app.auth.service import SECRET_KEY, ALGORITHM
from app.database.db import DB_PATH
import aiosqlite

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or expired token")

    # Reject refresh tokens used as access tokens
    if payload.get("type") == "refresh":
        raise HTTPException(status_code=401, detail="Use access token, not refresh token")

    user_id = payload.get("sub")
    email   = payload.get("email")
    jti     = payload.get("jti", "")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token claims")

    # Check revocation list
    if jti:
        async with aiosqlite.connect(DB_PATH) as db:
            async with db.execute(
                "SELECT 1 FROM revoked_tokens WHERE jti=?", (jti,)
            ) as cur:
                if await cur.fetchone():
                    raise HTTPException(status_code=401, detail="Token has been revoked")

    # Fetch full user record
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id, email, username FROM users WHERE id=?", (user_id,)
        ) as cur:
            row = await cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    return {"id": row[0], "email": row[1], "username": row[2]}
