"""
Vexor Cloud Sync + Team Collaboration API
Feature 13: Cloud Sync — CLI findings sync to web dashboard
Feature 14: Team Collaboration — multiple users on same target
"""
import asyncio
import json
import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from app.auth.dependencies import get_current_user
import aiosqlite

router = APIRouter()
DB_PATH = "vexor.db"


# ─── Models ──────────────────────────────────────────────────────────────────

class SyncRequest(BaseModel):
    target: str
    scan_type: str = "full"
    findings: list[dict] = []
    stats: dict = {}
    workspace: str = ""


class TeamProjectRequest(BaseModel):
    name: str
    target: str
    description: str = ""


class TeamInviteRequest(BaseModel):
    project_id: int
    invite_email: str


class FindingUpdateRequest(BaseModel):
    project_id: int
    findings: list[dict]


# ─── DB init ─────────────────────────────────────────────────────────────────

async def _ensure_sync_tables():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cloud_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                target      TEXT NOT NULL,
                scan_type   TEXT DEFAULT 'full',
                workspace   TEXT DEFAULT '',
                findings    TEXT DEFAULT '[]',
                stats       TEXT DEFAULT '{}',
                synced_at   TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS team_projects (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id    INTEGER NOT NULL,
                name        TEXT NOT NULL,
                target      TEXT NOT NULL,
                description TEXT DEFAULT '',
                created_at  TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS team_members (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER NOT NULL,
                user_id     INTEGER NOT NULL,
                role        TEXT DEFAULT 'member',
                joined_at   TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES team_projects(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS team_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER NOT NULL,
                user_id     INTEGER NOT NULL,
                findings    TEXT DEFAULT '[]',
                updated_at  TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES team_projects(id)
            )
        """)
        await db.commit()


# ─── Cloud Sync Endpoints ─────────────────────────────────────────────────────

@router.post("/push")
async def sync_push(req: SyncRequest, user=Depends(get_current_user)):
    """
    CLI pushes scan findings to cloud.
    Creates or updates a cloud scan record.
    """
    await _ensure_sync_tables()
    now = datetime.datetime.utcnow().isoformat()

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO cloud_scans (user_id, target, scan_type, workspace, findings, stats, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user["id"],
            req.target,
            req.scan_type,
            req.workspace,
            json.dumps(req.findings),
            json.dumps(req.stats),
            now,
        ))
        await db.commit()
        scan_id = cursor.lastrowid

    return {
        "message": "Synced successfully",
        "scan_id": scan_id,
        "synced_at": now,
        "findings_count": len(req.findings),
    }


@router.get("/history")
async def sync_history(limit: int = 20, user=Depends(get_current_user)):
    """Get user's cloud scan history"""
    await _ensure_sync_tables()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT id, target, scan_type, workspace, stats, synced_at
            FROM cloud_scans
            WHERE user_id = ?
            ORDER BY synced_at DESC
            LIMIT ?
        """, (user["id"], limit)) as cursor:
            rows = await cursor.fetchall()

    return [
        {
            "id": r["id"],
            "target": r["target"],
            "scan_type": r["scan_type"],
            "workspace": r["workspace"],
            "stats": json.loads(r["stats"] or "{}"),
            "synced_at": r["synced_at"],
        }
        for r in rows
    ]


@router.get("/findings/{scan_id}")
async def get_cloud_findings(scan_id: int, user=Depends(get_current_user)):
    """Get findings for a specific cloud scan"""
    await _ensure_sync_tables()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT findings FROM cloud_scans
            WHERE id = ? AND user_id = ?
        """, (scan_id, user["id"])) as cursor:
            row = await cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {"scan_id": scan_id, "findings": json.loads(row["findings"] or "[]")}


@router.delete("/scan/{scan_id}")
async def delete_cloud_scan(scan_id: int, user=Depends(get_current_user)):
    """Delete a cloud scan"""
    await _ensure_sync_tables()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM cloud_scans WHERE id = ? AND user_id = ?",
            (scan_id, user["id"])
        )
        await db.commit()
    return {"message": "Deleted"}


# ─── Team Collaboration Endpoints ─────────────────────────────────────────────

@router.post("/team/project")
async def create_team_project(req: TeamProjectRequest, user=Depends(get_current_user)):
    """Create a new team project"""
    await _ensure_sync_tables()
    now = datetime.datetime.utcnow().isoformat()

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO team_projects (owner_id, name, target, description, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user["id"], req.name, req.target, req.description, now))

        project_id = cursor.lastrowid

        # Add owner as member
        await db.execute("""
            INSERT INTO team_members (project_id, user_id, role, joined_at)
            VALUES (?, ?, 'owner', ?)
        """, (project_id, user["id"], now))

        await db.commit()

    return {"message": "Project created", "project_id": project_id}


@router.get("/team/projects")
async def list_team_projects(user=Depends(get_current_user)):
    """List all projects user is a member of"""
    await _ensure_sync_tables()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT p.id, p.name, p.target, p.description, p.created_at,
                   tm.role,
                   (SELECT COUNT(*) FROM team_members WHERE project_id = p.id) as member_count
            FROM team_projects p
            JOIN team_members tm ON p.id = tm.project_id
            WHERE tm.user_id = ?
            ORDER BY p.created_at DESC
        """, (user["id"],)) as cursor:
            rows = await cursor.fetchall()

    return [dict(r) for r in rows]


@router.post("/team/findings")
async def push_team_findings(req: FindingUpdateRequest, user=Depends(get_current_user)):
    """Push findings to a team project (real-time collaboration)"""
    await _ensure_sync_tables()
    now = datetime.datetime.utcnow().isoformat()

    # Verify user is a member
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id FROM team_members WHERE project_id = ? AND user_id = ?",
            (req.project_id, user["id"])
        ) as cursor:
            if not await cursor.fetchone():
                raise HTTPException(status_code=403, detail="Not a project member")

        # Upsert findings
        async with db.execute(
            "SELECT id FROM team_findings WHERE project_id = ? AND user_id = ?",
            (req.project_id, user["id"])
        ) as cursor:
            existing = await cursor.fetchone()

        if existing:
            await db.execute("""
                UPDATE team_findings SET findings = ?, updated_at = ?
                WHERE project_id = ? AND user_id = ?
            """, (json.dumps(req.findings), now, req.project_id, user["id"]))
        else:
            await db.execute("""
                INSERT INTO team_findings (project_id, user_id, findings, updated_at)
                VALUES (?, ?, ?, ?)
            """, (req.project_id, user["id"], json.dumps(req.findings), now))

        await db.commit()

    return {"message": "Findings synced", "count": len(req.findings)}


@router.get("/team/findings/{project_id}")
async def get_team_findings(project_id: int, user=Depends(get_current_user)):
    """Get all findings from all team members for a project"""
    await _ensure_sync_tables()

    # Verify membership
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT id FROM team_members WHERE project_id = ? AND user_id = ?",
            (project_id, user["id"])
        ) as cursor:
            if not await cursor.fetchone():
                raise HTTPException(status_code=403, detail="Not a project member")

        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT tf.findings, tf.updated_at, u.username, u.email
            FROM team_findings tf
            JOIN users u ON tf.user_id = u.id
            WHERE tf.project_id = ?
            ORDER BY tf.updated_at DESC
        """, (project_id,)) as cursor:
            rows = await cursor.fetchall()

    # Merge all findings
    all_findings = []
    contributors = []
    for row in rows:
        findings = json.loads(row["findings"] or "[]")
        all_findings.extend(findings)
        contributors.append({
            "username": row["username"],
            "email": row["email"],
            "updated_at": row["updated_at"],
            "count": len(findings),
        })

    return {
        "project_id": project_id,
        "total_findings": len(all_findings),
        "contributors": contributors,
        "findings": all_findings,
    }
