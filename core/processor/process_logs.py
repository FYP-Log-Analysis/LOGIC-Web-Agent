# Single streaming pass: reads raw_entries.json, parses each line, normalises it,
# and writes normalized_logs.json + compact behavioral aggregations to SQLite.
# Raw log rows are NOT stored in SQLite — the aggregation tables are far smaller
# and support all behavioral analysis and IP investigation features.
import json
import logging
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

import ijson

from core.processor.apache_norm import normalise_access_entry, normalise_nginx_error
from core.storage.sqlite_store import init_db, insert_behavioral_aggregations, upsert_ip_geo

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
    # Prefer the upload-scoped intermediate file to avoid concurrent upload conflicts
    scoped = (
        PROJECT_ROOT / "data" / "intermediate" / f"{upload_id}_raw_entries.json"
        if upload_id
        else None
    )
    src = (scoped if scoped and scoped.exists() else INTERMEDIATE)

    if not src.exists():
        logger.error(f"Raw entries not found: {src} — run ingestion first.")
        return 0

    NORMALISED_DIR.mkdir(parents=True, exist_ok=True)
    out_path = NORMALISED_DIR / "normalized_logs.json"

    written = skipped = 0
    first   = True

    # ── In-memory behavioural aggregation accumulators ──────────────────────
    # These are written to compact SQLite tables at the end in a single
    # transaction, replacing per-batch bulk_insert_logs calls.
    _rate:     defaultdict = defaultdict(int)          # (ip, min_bucket) -> count
    _enum_c:   defaultdict = defaultdict(int)          # (ip, hour_bucket) -> total requests
    _enum_p:   defaultdict = defaultdict(set)          # (ip, hour_bucket) -> set(paths, ≤20)
    _status:   defaultdict = defaultdict(lambda: [0, 0])  # min_bucket -> [total, errors]
    _visitors: defaultdict = defaultdict(set)          # hour_bucket -> set(unique IPs)
    _hour_tot: defaultdict = defaultdict(int)          # hour_bucket -> total requests
    _ip_sum:   dict        = {}                        # ip -> summary dict
    _total_count = 0
    _min_ts: str | None  = None
    _max_ts: str | None  = None

    _geo_batch: set[str] = set()
    _seen_ips:  set[str] = set()

    try:
        init_db()
    except Exception as exc:
        logger.warning(f"SQLite init skipped: {exc}")

    with open(src, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
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
            first        = False
            written     += 1
            _total_count += 1

            # ── Accumulate behavioural aggregation data ─────────────────────
            ts      = normalised.get("timestamp") or ""
            ip      = normalised.get("client_ip") or ""
            status  = normalised.get("status_code") or 0
            path    = normalised.get("path_clean") or normalised.get("request_path") or ""
            ua      = normalised.get("user_agent") or ""
            sc      = normalised.get("status_class") or ""

            if ts:
                if _min_ts is None or ts < _min_ts:
                    _min_ts = ts
                if _max_ts is None or ts > _max_ts:
                    _max_ts = ts
                min_bucket  = ts[:16]          # "2024-01-15T12:34"
                hour_bucket = ts[:13] + ":00"  # "2024-01-15T12:00"
                _status[min_bucket][0] += 1
                if status >= 400:
                    _status[min_bucket][1] += 1

                if ip:
                    _rate[(ip, min_bucket)] += 1
                    _enum_c[(ip, hour_bucket)] += 1
                    ep = _enum_p[(ip, hour_bucket)]
                    if path and len(ep) < 20:
                        ep.add(path)
                    _visitors[hour_bucket].add(ip)
                    _hour_tot[hour_bucket] += 1

            if ip:
                if ip not in _seen_ips:
                    _seen_ips.add(ip)
                    _geo_batch.add(ip)
                # Per-IP summary
                s = _ip_sum.get(ip)
                if s is None:
                    s = {
                        "count": 0, "first_ts": ts, "last_ts": ts,
                        "ua_ctr": Counter(), "status_ctr": Counter(), "path_ctr": Counter(),
                    }
                    _ip_sum[ip] = s
                s["count"] += 1
                if ts and ts < s["first_ts"]:
                    s["first_ts"] = ts
                if ts and ts > s["last_ts"]:
                    s["last_ts"] = ts
                if ua:
                    s["ua_ctr"][ua] += 1
                if sc:
                    s["status_ctr"][sc] += 1
                if path:
                    s["path_ctr"][path] += 1
                    # Prune to cap memory usage per IP (keep top 50, note count is approximate)
                    if len(s["path_ctr"]) > 200:
                        s["path_ctr"] = Counter(dict(s["path_ctr"].most_common(50)))

            if written % _LOG_EVERY == 0:
                logger.info(f"  … {written:,} entries processed")
        fout.write("\n]")

    # ── Flush GeoIP lookups ─────────────────────────────────────────────────
    if _geo_batch:
        try:
            upsert_ip_geo(list(_geo_batch))
        except Exception as exc:
            logger.warning(f"GeoIP batch upsert skipped: {exc}")

    # ── Write compact behavioural aggregations to SQLite ────────────────────
    try:
        insert_behavioral_aggregations(
            upload_id       = upload_id,
            project_id      = project_id,
            summary         = {
                "total_count":    _total_count,
                "min_ts":         _min_ts,
                "max_ts":         _max_ts,
                "unique_ip_count": len(_seen_ips),
            },
            rate_buckets    = _rate,
            enum_buckets_c  = _enum_c,
            enum_buckets_p  = _enum_p,
            status_buckets  = _status,
            visitor_buckets = _visitors,
            hour_totals     = _hour_tot,
            ip_summaries    = _ip_sum,
        )
    except Exception as exc:
        logger.warning(f"Behavioural aggregation write skipped: {exc}")

    logger.info(f"Processed {written:,} entries | Skipped {skipped}")
    logger.info(f"Saved → {out_path}")

    # Clean up the scoped intermediate file so disk space isn't wasted
    if scoped and scoped.exists():
        try:
            scoped.unlink()
        except Exception as exc:
            logger.warning(f"Could not delete intermediate file {scoped}: {exc}")

    return written


if __name__ == "__main__":
    process_all()
