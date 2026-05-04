"""Vexor Auth Router - input validation, rate limiting, refresh token, logout/revocation"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr, field_validator
from app.auth.service import AuthService
from app.auth.dependencies import get_current_user
from collections import defaultdict
import time

router  = APIRouter()
service = AuthService()

_auth_attempts: dict = defaultdict(list)
AUTH_RATE_LIMIT  = 10
AUTH_RATE_WINDOW = 300  # 5 minutes


def _check_auth_rate(client_ip: str) -> None:
    now = time.time()
    window_start = now - AUTH_RATE_WINDOW
    _auth_attempts[client_ip] = [t for t in _auth_attempts[client_ip] if t > window_start]
    if len(_auth_attempts[client_ip]) >= AUTH_RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Too many auth attempts. Try again in {AUTH_RATE_WINDOW // 60} minutes.",
        )
    _auth_attempts[client_ip].append(now)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    username: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("Username must be at least 2 characters")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    token: str


@router.post("/register")
async def register(req: RegisterRequest, request: Request):
    _check_auth_rate(request.client.host if request.client else "unknown")
    user = await service.register(email=req.email, password=req.password, username=req.username)
    if not user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"message": "Registered successfully", "user": user}


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    _check_auth_rate(request.client.host if request.client else "unknown")
    result = await service.login(email=req.email, password=req.password)
    if not result:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return result


@router.post("/refresh")
async def refresh_token(req: RefreshRequest):
    result = await service.refresh(req.refresh_token)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    return result


@router.post("/logout")
async def logout(req: LogoutRequest, user=Depends(get_current_user)):
    """Revoke a token — invalidates it server-side even before expiry."""
    success = await service.logout(req.token)
    return {"message": "Logged out successfully" if success else "Token already expired"}


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user
