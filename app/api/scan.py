"""
Scan Results API
"""
from fastapi import APIRouter, Depends
from app.auth.dependencies import get_current_user
import aiosqlite
import json

router = APIRouter()


@router.get("/results")
async def get_results(user=Depends(get_current_user)):
    async with aiosqlite.connect("vexor.db") as db:
        async with db.execute(
            "SELECT id, target, findings, created_at FROM scan_results WHERE user_id = ?",
            (user["id"],)
        ) as cursor:
            rows = await cursor.fetchall()
    return [
        {"id": r[0], "target": r[1], "findings": json.loads(r[2] or "[]"), "created_at": r[3]}
        for r in rows
    ]


@router.post("/save")
async def save_result(data: dict, user=Depends(get_current_user)):
    async with aiosqlite.connect("vexor.db") as db:
        await db.execute(
            "INSERT INTO scan_results (user_id, target, findings) VALUES (?, ?, ?)",
            (user["id"], data.get("target", ""), json.dumps(data.get("findings", [])))
        )
        await db.commit()
    return {"message": "Saved"}
