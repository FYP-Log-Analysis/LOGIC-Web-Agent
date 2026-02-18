"""
Ingestion Module — LOGIC Web Agent
Reads raw web server log files (plain .log or gzip-compressed .gz) from
data/raw_logs/ and writes a single JSON list of raw string entries to
data/intermediate/raw_entries.json for the parser stage.
"""

import os
import gzip
import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RAW_LOGS_DIR  = PROJECT_ROOT / "data" / "raw_logs"
INTERMEDIATE_DIR = PROJECT_ROOT / "data" / "intermediate"


def read_log_file(file_path: Path) -> list[str]:
    """Read lines from a plain or gzip-compressed log file."""
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


def ingest_all() -> list[dict]:
    """
    Walk raw_logs directory, read every .log / .gz file, and return a list of
    dicts with keys: 'source' (filename) and 'raw' (original log line).
    """
    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    INTERMEDIATE_DIR.mkdir(parents=True, exist_ok=True)

    entries = []
    log_files = sorted(
        [f for f in RAW_LOGS_DIR.iterdir()
         if f.is_file() and f.suffix in {".log", ".gz", ".txt"}]
    )

    if not log_files:
        logger.warning(f"No log files found in {RAW_LOGS_DIR}")
        return entries

    for log_file in log_files:
        lines = read_log_file(log_file)
        for line in lines:
            entries.append({"source": log_file.name, "raw": line})

    logger.info(f"Total entries ingested: {len(entries):,}")

    # Persist to intermediate
    out_path = INTERMEDIATE_DIR / "raw_entries.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    logger.info(f"Saved raw entries → {out_path}")

    return entries


if __name__ == "__main__":
    result = ingest_all()
    print(f"Ingestion complete: {len(result):,} entries")
