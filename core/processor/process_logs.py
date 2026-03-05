# Single streaming pass: reads raw_entries.json, parses each line, normalises it,
# and writes normalized_logs.json + inserts into SQLite. No intermediate files.
import json
import logging
import re
from datetime import datetime
from pathlib import Path

import ijson

from core.processor.apache_norm import normalise_access_entry, normalise_nginx_error
from core.storage.sqlite_store import init_db, bulk_insert_logs

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parents[2]
INTERMEDIATE   = PROJECT_ROOT / "data" / "intermediate" / "raw_entries.json"
NORMALISED_DIR = PROJECT_ROOT / "data" / "processed" / "normalized"

_LOG_EVERY = 50_000


# Apache / Nginx Combined Log Format
COMBINED_RE = re.compile(
    r'(?P<ip>\S+)'
    r'\s+\S+'
    r'\s+(?P<user>\S+)'
    r'\s+\[(?P<time>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<path>\S+)'
    r'\s+(?P<protocol>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"'
    r'\s+"(?P<user_agent>[^"]*)")?'
)

# Nginx error log: 2024/01/15 12:34:56 [error] 1234#0: *1 message, client: 1.2.3.4
NGINX_ERROR_RE = re.compile(
    r'(?P<time>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'
    r'\s+\[(?P<level>\w+)\]'
    r'.*?client:\s*(?P<ip>[\d\.]+)?'
    r'.*?(?P<message>.+)'
)

TIMESTAMP_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache/Nginx combined
    "%Y/%m/%d %H:%M:%S",       # Nginx error
    "%Y-%m-%dT%H:%M:%S%z",    # ISO 8601
]


def _parse_timestamp(raw: str) -> str:
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt).isoformat()
        except ValueError:
            continue
    return raw.strip()


def _detect_server_type(source: str) -> str:
    s = source.lower()
    if "nginx" in s:
        return "nginx"
    if "apache" in s or "httpd" in s:
        return "apache"
    return "apache"  # Combined Format default


def _parse_line(raw_line: str, source: str) -> dict | None:
    m = COMBINED_RE.match(raw_line)
    if m:
        g = m.groupdict()
        return {
            "source":     source,
            "log_type":   "access",
            "ip":         g["ip"],
            "user":       g["user"] if g["user"] != "-" else None,
            "timestamp":  _parse_timestamp(g["time"]),
            "method":     g["method"].upper(),
            "path":       g["path"],
            "protocol":   g.get("protocol", "").strip(),
            "status":     int(g["status"]),
            "size":       int(g["size"]) if g["size"].isdigit() else 0,
            "referer":    g.get("referer") or None,
            "user_agent": g.get("user_agent") or None,
            "raw":        raw_line,
        }

    m = NGINX_ERROR_RE.match(raw_line)
    if m:
        g = m.groupdict()
        return {
            "source":    source,
            "log_type":  "error",
            "ip":        g.get("ip"),
            "timestamp": _parse_timestamp(g["time"]),
            "level":     g.get("level"),
            "message":   g.get("message", "").strip(),
            "raw":       raw_line,
        }

    return None


def _normalise(parsed: dict) -> dict | None:
    log_type    = parsed.get("log_type", "access")
    server_type = _detect_server_type(parsed.get("source", ""))

    if log_type == "error":
        return normalise_nginx_error(parsed)
    return normalise_access_entry(parsed, server_type=server_type)


def process_all(upload_id: str | None = None, project_id: str | None = None) -> int:
    if not INTERMEDIATE.exists():
        logger.error(f"Raw entries not found: {INTERMEDIATE} — run ingestion first.")
        return 0

    NORMALISED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = NORMALISED_DIR / "normalized_logs.json"

    written = skipped = 0
    first   = True
    _sqlite_batch: list[dict] = []
    _BATCH_SIZE = 5_000

    try:
        init_db()
    except Exception as exc:
        logger.warning(f"SQLite init skipped: {exc}")

    with open(INTERMEDIATE, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
        fout.write("[\n")
        for raw_entry in ijson.items(fin, "item"):
            parsed = _parse_line(raw_entry["raw"], raw_entry["source"])
            if parsed is None:
                skipped += 1
                continue
            normalised = _normalise(parsed)
            if normalised is None:
                skipped += 1
                continue
            if not first:
                fout.write(",\n")
            fout.write(json.dumps(normalised, ensure_ascii=False))
            first   = False
            written += 1
            _sqlite_batch.append(normalised)
            if len(_sqlite_batch) >= _BATCH_SIZE:
                try:
                    bulk_insert_logs(_sqlite_batch, upload_id=upload_id, project_id=project_id)
                except Exception as exc:
                    logger.warning(f"SQLite log batch insert skipped: {exc}")
                _sqlite_batch.clear()
            if written % _LOG_EVERY == 0:
                logger.info(f"  … {written:,} entries processed")
        fout.write("\n]")

    # flush remaining batch
    if _sqlite_batch:
        try:
            bulk_insert_logs(_sqlite_batch, upload_id=upload_id, project_id=project_id)
        except Exception as exc:
            logger.warning(f"SQLite log final batch insert skipped: {exc}")

    logger.info(f"Processed {written:,} entries | Skipped {skipped}")
    logger.info(f"Saved → {out_path}")
    return written


if __name__ == "__main__":
    process_all()
