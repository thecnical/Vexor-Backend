"""
Vexor Auth Router
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from app.auth.service import AuthService
from app.auth.dependencies import get_current_user

router = APIRouter()
service = AuthService()


class RegisterRequest(BaseModel):
    email: str
    password: str
    username: str


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/register")
async def register(req: RegisterRequest):
    user = await service.register(
        email=req.email,
        password=req.password,
        username=req.username,
    )
    if not user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return {"message": "Registered successfully", "user": user}


@router.post("/login")
async def login(req: LoginRequest):
    result = await service.login(email=req.email, password=req.password)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    return result


@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user
