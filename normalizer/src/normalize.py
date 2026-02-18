"""
Normalization Dispatcher — LOGIC Web Agent
Loads parsed logs from data/processed/json/parsed_logs.json,
routes each entry to the appropriate normalizer, and saves results to
data/processed/normalized/normalized_logs.json.
"""

import json
import logging
from pathlib import Path

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


def _detect_server_type(source: str) -> str:
    """Guess server type from filename heuristic."""
    source_lower = source.lower()
    if "nginx" in source_lower:
        return "nginx"
    if "apache" in source_lower or "httpd" in source_lower:
        return "apache"
    return "apache"  # default to Apache (both share Combined Format)


def normalise_entry(entry: dict) -> dict | None:
    log_type    = entry.get("log_type", "access")
    source      = entry.get("source", "")
    server_type = _detect_server_type(source)

    if log_type == "error":
        return normalise_nginx_error(entry)
    if server_type == "nginx":
        return normalise_nginx_access(entry)
    return normalise_apache_entry(entry)


def normalise_all() -> list[dict]:
    """Normalise all parsed log entries and persist results."""
    if not PARSED_FILE.exists():
        logger.error(f"Parsed logs not found: {PARSED_FILE}  — run parser first.")
        return []

    with open(PARSED_FILE, "r", encoding="utf-8") as fh:
        parsed = json.load(fh)

    normalised = []
    for entry in parsed:
        result = normalise_entry(entry)
        if result:
            normalised.append(result)

    logger.info(f"Normalised {len(normalised):,} entries")

    NORMALISED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = NORMALISED_DIR / "normalized_logs.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(normalised, fh, indent=2)
    logger.info(f"Saved → {out_path}")

    return normalised


if __name__ == "__main__":
    result = normalise_all()
    print(f"Normalisation complete: {len(result):,} records")
