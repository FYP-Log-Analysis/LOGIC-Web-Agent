"""
Parser Module — LOGIC Web Agent
Converts raw log line entries (from data/intermediate/raw_entries.json) into
structured JSON objects using Apache/Nginx Combined Log Format regex.
Output → data/processed/json/parsed_logs.json
"""

import re
import json
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parents[2]
INTERMEDIATE   = PROJECT_ROOT / "data" / "intermediate" / "raw_entries.json"
PROCESSED_JSON = PROJECT_ROOT / "data" / "processed" / "json"

# Combined Log Format  (Apache & Nginx default)
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/5.0"
COMBINED_RE = re.compile(
    r'(?P<ip>\S+)'            # client IP
    r'\s+\S+'                 # ident (usually -)
    r'\s+(?P<user>\S+)'       # auth user
    r'\s+\[(?P<time>[^\]]+)\]'
    r'\s+"(?P<method>\S+)'
    r'\s+(?P<path>\S+)'
    r'\s+(?P<protocol>[^"]+)"'
    r'\s+(?P<status>\d{3})'
    r'\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"'
    r'\s+"(?P<user_agent>[^"]*)")?'
)

# Nginx error log
# 2024/01/15 12:34:56 [error] 1234#0: *1 message, client: 1.2.3.4, server: localhost
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
    """Try multiple formats; return ISO 8601 string or the original."""
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            return dt.isoformat()
        except ValueError:
            continue
    return raw.strip()


def parse_line(raw_line: str, source: str) -> dict | None:
    """
    Attempt to parse a single log line.
    Returns a structured dict or None if the line cannot be parsed.
    """
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


def parse_all() -> list[dict]:
    """Load raw entries, parse each line, save to processed/json/."""
    if not INTERMEDIATE.exists():
        logger.error(f"Raw entries file not found: {INTERMEDIATE}  — run ingestion first.")
        return []

    with open(INTERMEDIATE, "r", encoding="utf-8") as fh:
        raw_entries = json.load(fh)

    parsed, skipped = [], 0
    for entry in raw_entries:
        result = parse_line(entry["raw"], entry["source"])
        if result:
            parsed.append(result)
        else:
            skipped += 1

    logger.info(f"Parsed {len(parsed):,} entries | Skipped {skipped:,} unrecognised lines")

    PROCESSED_JSON.mkdir(parents=True, exist_ok=True)
    out_path = PROCESSED_JSON / "parsed_logs.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(parsed, fh, indent=2)
    logger.info(f"Saved parsed logs → {out_path}")

    return parsed


if __name__ == "__main__":
    result = parse_all()
    print(f"Parsing complete: {len(result):,} records")
