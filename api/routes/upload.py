"""
Upload Route — LOGIC Web Agent
Accepts a single .log/.gz file or a .zip/.tar archive, saves it to
data/raw_logs/, then runs ONLY ingestion + normalisation as a background
task.  ML and rule-based analysis are NOT triggered automatically; they
must be started explicitly via POST /api/analysis/run.

Progress can be polled via GET /api/upload/status/{upload_id}.
"""

import os
import shutil
import tarfile
import tempfile
import uuid
import zipfile
import logging
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile

from analysis.sqlite_store import (
    init_db,
    insert_upload_status,
    update_upload_status,
    get_upload_status,
    get_log_time_range,
)

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_EXT  = {".zip", ".tar", ".gz", ".tgz", ".log"}
RAW_LOGS_DIR = Path(__file__).resolve().parents[2] / "data" / "raw_logs"


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


def _ingest_and_normalise(upload_id: str) -> None:
    """
    Background task: run ingestion + normalisation only, update progress
    stages in SQLite upload_status table after each step.
    Does NOT run rule_analysis or ml_analysis.
    """
    from ingestion.ingest_logs import ingest_all
    from processor.process_logs import process_all

    try:
        # Stage 1 — Parsing (ingestion reads raw files → raw_entries.json)
        update_upload_status(upload_id, stage="parsing", status="running")
        ingest_all()
        update_upload_status(upload_id, stage="parsing", status="complete")

        # Stage 2 — Normalisation (process_logs → normalized_logs.json + SQLite logs table)
        update_upload_status(upload_id, stage="normalizing", status="running")
        entry_count = process_all(upload_id=upload_id)
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

    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    upload_id = str(uuid.uuid4())
    tmp       = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        if suffix == ".zip":
            _safe_extract_zip(tmp_file, RAW_LOGS_DIR)
            saved_name = file.filename
        elif suffix in {".tar", ".tgz"}:
            _safe_extract_tar(tmp_file, RAW_LOGS_DIR)
            saved_name = file.filename
        else:
            dest = RAW_LOGS_DIR / file.filename
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
    background_tasks.add_task(_ingest_and_normalise, upload_id)

    return {
        "status":    "accepted",
        "upload_id": upload_id,
        "filename":  saved_name,
        "message":   "Ingestion started. Poll GET /api/upload/status/{upload_id} for progress.",
    }


@router.get("/upload/status/{upload_id}")
async def get_upload_progress(upload_id: str) -> dict:
    """
    Poll the current stage and status of an upload.
    Stages: uploading → parsing → normalizing → saved
    Status: running | complete | error
    """
    record = get_upload_status(upload_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No upload found with id '{upload_id}'")
    return record


@router.get("/logs/time-range")
async def log_time_range() -> dict:
    """
    Return the earliest and latest timestamp stored in the logs table.
    Used by the frontend time-range slider for manual analysis mode.
    """
    return get_log_time_range()

