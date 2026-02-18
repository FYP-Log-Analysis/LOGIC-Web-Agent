from fastapi import APIRouter, File, UploadFile, HTTPException
import os
import zipfile
import tarfile
import tempfile
import shutil
from pathlib import Path
from api.services.pipeline_service import run_pipeline

router = APIRouter()

ALLOWED_MIME = {"application/zip", "application/x-tar", "application/gzip",
                "application/x-gzip", "application/octet-stream"}
ALLOWED_EXT  = {".zip", ".tar", ".gz", ".tgz", ".log"}


@router.post("/upload")
async def upload_logs(file: UploadFile = File(...)):
    """
    Upload web server logs as a ZIP/tar archive or a single .log/.gz file.
    Files are extracted to data/raw_logs/ and the pipeline runs automatically.
    """
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_EXT:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{suffix}'. Allowed: {ALLOWED_EXT}",
        )

    raw_logs_dir = Path(__file__).resolve().parents[2] / "data" / "raw_logs"
    raw_logs_dir.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp()

    try:
        tmp_file = os.path.join(tmp, file.filename)
        with open(tmp_file, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        if suffix == ".zip":
            with zipfile.ZipFile(tmp_file, "r") as zf:
                zf.extractall(raw_logs_dir)
        elif suffix in {".tar", ".tgz"}:
            with tarfile.open(tmp_file) as tf:
                tf.extractall(raw_logs_dir)
        else:
            # Single .log or .gz — move directly
            shutil.copy(tmp_file, raw_logs_dir / file.filename)

        result = run_pipeline()
        return {"message": "Logs uploaded and pipeline executed", "pipeline_result": result}

    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Processing failed: {exc}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
