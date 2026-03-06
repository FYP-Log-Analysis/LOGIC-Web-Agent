import os
import shutil
import tarfile
import tempfile
import uuid
import zipfile
import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, UploadFile

from core.storage.sqlite_store import (
    init_db,
    insert_upload_status,
    update_upload_status,
    get_upload_status,
    get_log_time_range,
    query_logs,
    get_project,
)
from api.deps import UserInDB, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_EXT  = {".zip", ".tar", ".gz", ".tgz", ".log"}
RAW_LOGS_DIR = Path(__file__).resolve().parents[2] / "data" / "raw_logs"
PROJECTS_DIR = Path(__file__).resolve().parents[2] / "data" / "projects"


def _raw_logs_dir(project_id: str | None) -> Path:
    """Return the correct raw_logs directory for the given project (or legacy global)."""
    if project_id:
        return PROJECTS_DIR / project_id / "raw_logs"
    return RAW_LOGS_DIR


def _safe_extract_zip(zip_path: str, dest: Path) -> None:
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member}")
        zf.extractall(dest)


def _safe_extract_tar(tar_path: str, dest: Path) -> None:
    dest = dest.resolve()
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member.name}")
        tf.extractall(dest)


def _ingest_and_normalise(upload_id: str, project_id: str | None = None) -> None:
    from core.ingestion.ingest_logs import ingest_all
    from core.processor.process_logs import process_all

    # Resolve the working directory for this upload
    raw_dir = _raw_logs_dir(project_id)

    try:
        # Stage 1 — Parsing (ingestion reads raw files → {upload_id}_raw_entries.json)
        update_upload_status(upload_id, stage="parsing", status="running")
        ingest_all(raw_logs_dir=str(raw_dir), upload_id=upload_id)
        update_upload_status(upload_id, stage="parsing", status="complete")

        # Stage 2 — Normalisation (process_logs → normalized_logs.json + SQLite logs table)
        update_upload_status(upload_id, stage="normalizing", status="running")
        entry_count = process_all(upload_id=upload_id, project_id=project_id)
        update_upload_status(
            upload_id,
            stage="saved",
            status="complete",
            entry_count=entry_count,
        )

    except Exception as exc:
        logger.error(f"Upload background task failed: {exc}", exc_info=True)
        update_upload_status(
            upload_id,
            stage="error",
            status="error",
            error_msg=str(exc)[:500],
        )


@router.post("/upload", status_code=202)
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    project_id: str | None = Form(default=None),
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    """
    Upload web server logs (.log / .gz / .zip / .tar / .tgz).
    Files are saved to data/raw_logs/ and ingestion + normalisation run
    in the background.  Returns 202 Accepted with an upload_id.
    Poll GET /api/upload/status/{upload_id} for progress.
    """
    suffix = Path(file.filename or "unknown").suffix.lower()
    if suffix not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {sorted(ALLOWED_EXT)}",
        )

    # Validate project ownership
    if project_id:
        proj = get_project(project_id)
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        if proj["owner_id"] != current_user.id and current_user.role != "admin":
            raise HTTPException(status_code=403, detail="Not your project")

    dest_dir = _raw_logs_dir(project_id)
    dest_dir.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    tmp       = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        if suffix == ".zip":
            _safe_extract_zip(tmp_file, dest_dir)
            saved_name = file.filename
        elif suffix in {".tar", ".tgz"}:
            _safe_extract_tar(tmp_file, dest_dir)
            saved_name = file.filename
        else:
            dest = dest_dir / file.filename
            shutil.copy(tmp_file, dest)
            saved_name = file.filename

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"File processing failed: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    init_db()
    insert_upload_status(upload_id)
    background_tasks.add_task(_ingest_and_normalise, upload_id, project_id)

    return {
        "status":     "accepted",
        "upload_id":  upload_id,
        "filename":   saved_name,
        "project_id": project_id,
        "message":    "Ingestion started. Poll GET /api/upload/status/{upload_id} for progress.",
    }


@router.get("/upload/status/{upload_id}")
async def get_upload_progress(
    upload_id: str,
    current_user: UserInDB = Depends(get_current_user),
) -> dict:
    record = get_upload_status(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No upload found with id '{upload_id}'")
    return record


@router.get("/logs/time-range")
async def log_time_range(current_user: UserInDB = Depends(get_current_user)) -> dict:
    return get_log_time_range()


@router.get("/logs/entries")
async def get_log_entries(
    limit:      int       = Query(5000, le=10000, description="Max rows to return"),
    project_id: str | None = Query(None, description="Scope to a specific project"),
    _user:      UserInDB  = Depends(get_current_user),
) -> list:
    """Return normalised log entries from the SQLite store."""
    return query_logs(limit=limit, project_id=project_id)

