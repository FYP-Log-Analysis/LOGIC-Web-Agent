"""
api/routes/projects.py — Project CRUD
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POST   /api/projects              — create project (authenticated)
GET    /api/projects              — list own projects
GET    /api/projects/{id}         — get one project (owner or admin)
DELETE /api/projects/{id}         — delete project + all files (owner or admin)
GET    /api/projects/{id}/stats   — log/detection counts for a project
"""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.storage.sqlite_store import (
    create_project,
    delete_project,
    get_project,
    get_project_stats,
    list_projects_for_user,
)
from api.deps import UserInDB, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = PROJECT_ROOT / "data" / "projects"


def _project_dir(project_id: str) -> Path:
    return PROJECTS_DIR / project_id


# ── Request models ─────────────────────────────────────────────────────────────

class CreateProjectRequest(BaseModel):
    name:        str
    description: str = ""


# ── Helpers ────────────────────────────────────────────────────────────────────

def _assert_access(project: dict, user: UserInDB) -> None:
    """Raise 403 if the caller does not own the project and is not an admin."""
    if project["owner_id"] != user.id and user.role != "admin":
        raise HTTPException(403, "You do not have access to this project.")


def _assert_exists(project_id: str) -> dict:
    project = get_project(project_id)
    if not project:
        raise HTTPException(404, f"Project '{project_id}' not found.")
    return project


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/projects", status_code=201)
async def create_new_project(
    req:          CreateProjectRequest,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Create a new project.
    Initialises the per-project directory structure under data/projects/{id}/.
    """
    name = req.name.strip()
    if not name:
        raise HTTPException(400, "Project name cannot be empty.")

    project_id = str(uuid.uuid4())

    # Create directory skeleton
    base = _project_dir(project_id)
    for subdir in ["raw_logs", "intermediate", "processed/normalized", "detection_results"]:
        (base / subdir).mkdir(parents=True, exist_ok=True)

    project = create_project(
        project_id  = project_id,
        name        = name,
        description = req.description.strip(),
        owner_id    = current_user.id,
    )
    logger.info("Project created: %s ('%s') by user %s", project_id, name, current_user.username)
    return project


@router.get("/projects")
async def list_projects(
    current_user: UserInDB = Depends(get_current_user),
) -> list:
    """Return all projects owned by the current user."""
    return list_projects_for_user(current_user.id)


@router.get("/projects/{project_id}")
async def get_one_project(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    return project


@router.get("/projects/{project_id}/stats")
async def project_stats(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    project = _assert_exists(project_id)
    _assert_access(project, current_user)
    stats = get_project_stats(project_id)
    return {"project_id": project_id, **stats}


@router.delete("/projects/{project_id}", status_code=204)
async def remove_project(
    project_id:   str,
    current_user: UserInDB = Depends(get_current_user),
) -> None:
    """
    Delete a project, all its database rows, and its file tree on disk.
    Only the owner or an admin may delete a project.
    """
    project = _assert_exists(project_id)
    _assert_access(project, current_user)

    # Delete data files
    base = _project_dir(project_id)
    if base.exists():
        shutil.rmtree(base, ignore_errors=True)

    # Delete DB rows (cascades through logs/detections/etc.)
    delete_project(project_id)
    logger.info("Project deleted: %s by user %s", project_id, current_user.username)
