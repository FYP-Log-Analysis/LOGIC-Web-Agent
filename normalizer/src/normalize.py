"""
Normalization Dispatcher — LOGIC Web Agent
Streams parsed logs from data/processed/json/parsed_logs.json entry-by-entry
using ijson (so the full file is never held in RAM), routes each entry to the
appropriate normalizer, and writes results incrementally to
data/processed/normalized/normalized_logs.json.
"""

import json
import logging
from pathlib import Path

import ijson  # streaming JSON parser — avoids loading 600 MB+ file into RAM

try:
    from normalizer.src.apache_norm import normalise_apache_entry
    from normalizer.src.nginx_norm  import normalise_nginx_access, normalise_nginx_error
except ImportError:
    from apache_norm import normalise_apache_entry
    from nginx_norm  import normalise_nginx_access, normalise_nginx_error

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parents[2]
PARSED_FILE    = PROJECT_ROOT / "data" / "processed" / "json" / "parsed_logs.json"
NORMALISED_DIR = PROJECT_ROOT / "data" / "processed" / "normalized"

_CHUNK_LOG = 50_000   # log progress every N entries


def _detect_server_type(source: str) -> str:
    """Guess server type from filename heuristic."""
    source_lower = source.lower()
    if "nginx" in source_lower:
        return "nginx"
    if "apache" in source_lower or "httpd" in source_lower:
        return "apache"
    return "apache"  # default — both Apache and Nginx share Combined Format


def normalise_entry(entry: dict) -> dict | None:
    log_type    = entry.get("log_type", "access")
    source      = entry.get("source", "")
    server_type = _detect_server_type(source)

    if log_type == "error":
        return normalise_nginx_error(entry)
    if server_type == "nginx":
        return normalise_nginx_access(entry)
    return normalise_apache_entry(entry)


def normalise_all() -> int:
    """
    Stream-normalise all parsed log entries and persist results.
    Writes the output JSON array incrementally — peak RAM stays constant
    regardless of input size.
    Returns the number of entries written.
    """
    if not PARSED_FILE.exists():
        logger.error(f"Parsed logs not found: {PARSED_FILE}  — run parser first.")
        return 0

    NORMALISED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = NORMALISED_DIR / "normalized_logs.json"

    written  = 0
    skipped  = 0
    first    = True

    with open(PARSED_FILE, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
        fout.write("[\n")
        for entry in ijson.items(fin, "item"):
            result = normalise_entry(entry)
            if result is None:
                skipped += 1
                continue
            if not first:
                fout.write(",\n")
            fout.write(json.dumps(result, ensure_ascii=False))
            first   = False
            written += 1
            if written % _CHUNK_LOG == 0:
                logger.info(f"  … {written:,} entries normalised")
        fout.write("\n]")

    logger.info(f"Normalised {written:,} entries | Skipped {skipped:,}")
    logger.info(f"Saved → {out_path}")
    return written


if __name__ == "__main__":
    count = normalise_all()
    print(f"Normalisation complete: {count:,} records")

