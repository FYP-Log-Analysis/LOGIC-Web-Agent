"""
Upload Route — LOGIC Web Agent
Accepts a single .log/.gz file or a .zip/.tar archive, saves it to
data/raw_logs/, then triggers the full pipeline as a background task.
Responds 202 Accepted immediately so the HTTP client is not kept waiting.
"""

import os
import shutil
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile

from analysis.sqlite_store import init_db, insert_pipeline_run, update_pipeline_run
from api.services.pipeline_service import run_pipeline

router = APIRouter()

ALLOWED_EXT  = {".zip", ".tar", ".gz", ".tgz", ".log"}
RAW_LOGS_DIR = Path(__file__).resolve().parents[2] / "data" / "raw_logs"


def _safe_extract_zip(zip_path: str, dest: Path) -> None:
    """Extract a zip archive, rejecting any member that escapes dest (zip-slip fix)."""
    dest = dest.resolve()
    with zipfile.ZipFile(zip_path, "r") as zf:
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member}")
        zf.extractall(dest)


def _safe_extract_tar(tar_path: str, dest: Path) -> None:
    """Extract a tar archive, rejecting any member that escapes dest (tar-slip fix)."""
    dest = dest.resolve()
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            target = (dest / member.name).resolve()
            if not str(target).startswith(str(dest)):
                raise ValueError(f"Unsafe path in archive: {member.name}")
        tf.extractall(dest)


def _run_pipeline_task(run_id: str) -> None:
    """Background task: run full pipeline and update run record in SQLite."""
    try:
        update_pipeline_run(run_id, status="running")
        result = run_pipeline()

        # Collect counts from result steps
        entries    = next((s.get("output", "") for s in result.get("steps", []) if s.get("step_id") == "ingestion"), None)
        detections = None
        anomalies  = None

        update_pipeline_run(
            run_id,
            status="complete",
            entries=entries,
            detections=detections,
            anomalies=anomalies,
        )
    except Exception as exc:
        update_pipeline_run(run_id, status="failed", error_msg=str(exc)[:500])


@router.post("/upload", status_code=202)
async def upload_logs(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> dict:
    """
    Upload web server logs as a .log/.gz file or a .zip/.tar archive.
    The file is saved to data/raw_logs/ and the pipeline runs in the background.
    Returns 202 Accepted immediately with a run_id you can poll for status.
    """
    suffix = Path(file.filename or "unknown").suffix.lower()
    if suffix not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {sorted(ALLOWED_EXT)}",
        )

    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    run_id = str(uuid.uuid4())
    tmp    = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        file_size = os.path.getsize(tmp_file)

        if suffix == ".zip":
            _safe_extract_zip(tmp_file, RAW_LOGS_DIR)
            saved_name = file.filename
        elif suffix in {".tar", ".tgz"}:
            _safe_extract_tar(tmp_file, RAW_LOGS_DIR)
            saved_name = file.filename
        else:
            # Single .log or .gz — copy directly
            dest = RAW_LOGS_DIR / file.filename
            shutil.copy(tmp_file, dest)
            saved_name = file.filename

    except ValueError as exc:
        # zip/tar slip detected
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"File processing failed: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # Record this run in SQLite, then trigger pipeline in background
    init_db()
    insert_pipeline_run(run_id, source_file=saved_name, file_size=file_size)
    background_tasks.add_task(_run_pipeline_task, run_id)

    return {
        "status":   "accepted",
        "run_id":   run_id,
        "filename": saved_name,
        "message":  f"Pipeline started. Poll GET /api/pipeline/runs/{run_id} for status.",
    }

