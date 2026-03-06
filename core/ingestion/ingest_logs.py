# Reads raw log files (.log, .gz, .txt) from data/raw_logs/ and
# writes them as structured JSON to data/intermediate/raw_entries.json.
import gzip
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT     = Path(__file__).resolve().parents[2]
RAW_LOGS_DIR     = PROJECT_ROOT / "data" / "raw_logs"
INTERMEDIATE_DIR = PROJECT_ROOT / "data" / "intermediate"


def read_log_file(file_path: Path) -> list[str]:
    lines = []
    try:
        if file_path.suffix == ".gz":
            with gzip.open(file_path, "rt", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        else:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        logger.info(f"Read {len(lines):,} lines from {file_path.name}")
    except Exception as exc:
        logger.error(f"Failed to read {file_path}: {exc}")
    return [line.rstrip("\n") for line in lines if line.strip()]


def ingest_all(
    raw_logs_dir: str | None = None,
    upload_id: str | None = None,
) -> list[dict]:
    # Use caller-supplied directory (for project-scoped uploads) or global default
    source_dir = Path(raw_logs_dir) if raw_logs_dir else RAW_LOGS_DIR
    source_dir.mkdir(parents=True, exist_ok=True)
    INTERMEDIATE_DIR.mkdir(parents=True, exist_ok=True)

    entries    = []
    log_files  = sorted(
        f for f in source_dir.iterdir()
        if f.is_file() and f.suffix in {".log", ".gz", ".txt"}
    )

    if not log_files:
        logger.warning(f"No log files found in {source_dir}")
        return entries

    for log_file in log_files:
        for line in read_log_file(log_file):
            entries.append({"source": log_file.name, "raw": line})

    # Scope the intermediate file by upload_id to prevent concurrent uploads
    # from overwriting each other's data.
    fname = f"{upload_id}_raw_entries.json" if upload_id else "raw_entries.json"
    out_path = INTERMEDIATE_DIR / fname
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh)

    logger.info(f"Total entries ingested: {len(entries):,}")
    logger.info(f"Saved raw entries → {out_path}")
    return entries


if __name__ == "__main__":
    ingest_all()
