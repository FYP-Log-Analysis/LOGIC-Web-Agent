"""
CRS Processor — LOGIC Web Agent
# CRS INTEGRATION

Replays normalised log entries against the OWASP ModSecurity CRS detection
service and extracts all matched rule details from the JSON audit log.

Architecture:
  1. Stream normalized_logs.json entry by entry via ijson (no OOM risk).
  2. For each entry, send an HTTP request to the crs-detector service
     with a unique X-Logic-TxId header so the audit entry can be matched
     back to the original log entry.
  3. After all batches are replayed, sleep briefly for nginx to flush the
     audit log buffer, then parse the NDJSON audit log.
  4. Return a list of structured CRS match dicts ready for SQLite insertion.

Configuration (via environment variables):
  CRS_SERVICE_URL   — default: http://crs-detector:80
  CRS_AUDIT_LOG     — default: data/crs_audit/audit.log
  CRS_BATCH_SIZE    — default: 100 (requests per batch)
  CRS_FLUSH_WAIT    — default: 2  (seconds to wait for log flush after replay)

The module degrades gracefully: if the crs-detector service is unreachable
(e.g., running run_pipeline.py locally outside Docker), it logs a warning and
returns an empty list without raising any exception.
"""

import json
import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode, urlparse

import ijson
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

_PROJECT_ROOT   = Path(__file__).resolve().parent.parent.parent
_DEFAULT_AUDIT  = str(_PROJECT_ROOT / "data" / "crs_audit" / "audit.log")

CRS_SERVICE_URL = os.getenv("CRS_SERVICE_URL",  "http://crs-detector:8080")
CRS_AUDIT_LOG   = os.getenv("CRS_AUDIT_LOG",    _DEFAULT_AUDIT)
CRS_BATCH_SIZE  = int(os.getenv("CRS_BATCH_SIZE", "500"))
CRS_FLUSH_WAIT  = float(os.getenv("CRS_FLUSH_WAIT", "10"))
CRS_TIMEOUT     = float(os.getenv("CRS_TIMEOUT",  "2"))
CRS_WORKERS     = int(os.getenv("CRS_WORKERS",  "20"))

# Unique sentinel so we can locate our requests in the audit log
_TX_HEADER = "X-Logic-TxId"

# HTTP methods that typically carry a body
_BODY_METHODS = {"POST", "PUT", "PATCH"}


# ── HTTP session ──────────────────────────────────────────────────────────────

def _build_session() -> requests.Session:
    """Build a requests.Session with retry and connection pooling."""
    session = requests.Session()
    retry = Retry(
        total=1,
        backoff_factor=0.2,
        status_forcelist=[503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_maxsize=CRS_WORKERS * 2)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    return session


# ── Availability check ─────────────────────────────────────────────────────────

def check_crs_available() -> bool:
    """Return True if the crs-detector service responds to a HEAD request.

    Called at the start of run_crs_detection() so we can skip gracefully when
    running outside Docker without cluttering the logs with connection errors.
    """
    try:
        resp = requests.head(CRS_SERVICE_URL, timeout=3)
        return True  # any HTTP response = service is up
    except Exception:
        return False


# ── Request builder ────────────────────────────────────────────────────────────

def _build_request(entry: dict, tx_id: str) -> dict:
    """Convert a normalised log entry into requests.request() kwargs.

    Returns a dict of kwargs suitable for session.request(**kwargs).
    """
    method  = (entry.get("http_method") or "GET").upper()
    path    = entry.get("request_path") or "/"
    qs      = entry.get("query_string") or ""
    ua      = entry.get("user_agent")   or "LOGIC-CRS-Replay/1.0"
    ip      = entry.get("client_ip")    or "127.0.0.1"
    referer = entry.get("referer")      or ""

    # Build full URL: base URL + path (+ query string if present)
    base = CRS_SERVICE_URL.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if qs and not qs.startswith("?"):
        url = f"{base}{path}?{qs}"
    elif qs:
        url = f"{base}{path}{qs}"
    else:
        url = f"{base}{path}"

    headers = {
        _TX_HEADER:       tx_id,          # unique marker for audit log matching
        "User-Agent":     ua,
        "X-Forwarded-For": ip,
        "X-Real-IP":      ip,
    }
    if referer and referer not in ("-", ""):
        headers["Referer"] = referer

    # For POST/PUT entries, send a minimal form body so CRS body inspection fires
    data = None
    if method in _BODY_METHODS:
        # Use the query string as a POST body if available; otherwise empty form
        data = qs if qs else "logic=replay"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    return {
        "method":  method,
        "url":     url,
        "headers": headers,
        "data":    data,
        "timeout": CRS_TIMEOUT,
        "allow_redirects": False,
        "verify": False,
    }


# ── Replay engine ─────────────────────────────────────────────────────────────

def _replay_entries(
    entries: list[dict],
    session: requests.Session,
) -> dict[str, dict]:
    """Send all entries to the CRS service concurrently using a thread pool.

    Returns a mapping of tx_id → original entry.
    Connection errors are swallowed — we return whatever mapping we built.
    """
    # Build the full tx_map first (UUID assignment is cheap)
    tx_map: dict[str, dict] = {tx_id: entry
                                for tx_id, entry in
                                ((str(uuid.uuid4()), e) for e in entries)}

    def _send(tx_id: str) -> None:
        kwargs = _build_request(tx_map[tx_id], tx_id)
        try:
            session.request(**kwargs)
        except Exception:
            pass  # 502 from no backend is expected; silently skip

    with ThreadPoolExecutor(max_workers=CRS_WORKERS) as pool:
        futures = {pool.submit(_send, tx_id): tx_id for tx_id in tx_map}
        for fut in as_completed(futures):
            fut.result()  # re-raise unexpected exceptions to surface bugs

    return tx_map


# ── Audit log parser ──────────────────────────────────────────────────────────

def _parse_audit_log(
    audit_path: str,
    tx_map: dict[str, dict],
    start_offset: int = 0,
) -> list[dict]:
    """Parse the ModSecurity NDJSON audit log and extract CRS matches.

    start_offset: byte offset to start reading from (skip entries written
    before the current replay started, so old runs don't pollute results).

    Returns a list of match dicts ready for bulk_insert_crs_matches().
    """
    path = Path(audit_path)
    if not path.exists() or path.stat().st_size == 0:
        logger.warning(f"[CRS] Audit log not found or empty: {audit_path}")
        return []

    matches: list[dict] = []
    lines_read  = 0
    lines_error = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        if start_offset:
            fh.seek(start_offset)
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            lines_read += 1
            try:
                record = json.loads(raw_line)
            except json.JSONDecodeError:
                lines_error += 1
                continue

            tx = record.get("transaction", {})

            # ── Find our transaction ID in the request headers ─────────────
            req_headers = {}
            req_section = tx.get("request", {})
            if isinstance(req_section, dict):
                req_headers = req_section.get("headers", {}) or {}
                # ModSecurity lower-cases header names in some versions
                req_headers_lower = {k.lower(): v for k, v in req_headers.items()}

            tx_id = req_headers.get(_TX_HEADER) or req_headers_lower.get(
                _TX_HEADER.lower(), ""
            )

            if not tx_id or tx_id not in tx_map:
                continue  # Not one of our replayed entries

            original_entry = tx_map[tx_id]

            # ── Extract rule match messages ─────────────────────────────────
            messages = tx.get("messages", []) or []
            if not messages:
                # No rule fired — skip (MODSEC_AUDIT_ENGINE=RelevantOnly should
                # prevent this, but be defensive)
                continue

            # Pull the anomaly score from the request-level meta if available
            # (set by CRS rule 949110 / 980130)
            tx_anomaly_score = 0
            request_score = tx.get("request", {})
            # Some CRS versions surface the total score under transaction root
            if isinstance(tx.get("score"), dict):
                tx_anomaly_score = tx["score"].get("inbound", 0) or 0
            elif isinstance(tx.get("anomaly_score"), (int, float)):
                tx_anomaly_score = tx["anomaly_score"]

            for msg in messages:
                if not isinstance(msg, dict):
                    continue

                details  = msg.get("details", {}) or {}
                rule_id  = str(details.get("ruleId", "") or msg.get("ruleId", "") or "")
                message  = details.get("message", "") or msg.get("message", "") or ""
                tags_raw = details.get("tags", []) or msg.get("tags", []) or []
                tags     = tags_raw if isinstance(tags_raw, list) else [str(tags_raw)]

                # Paranoia level is carried in tags as "paranoia-level/N"
                paranoia_level = 1
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith("paranoia-level/"):
                        try:
                            paranoia_level = int(tag.split("/")[1])
                        except (IndexError, ValueError):
                            pass

                # Per-message anomaly score (CRS scores individual rules too)
                try:
                    msg_score = float(
                        details.get("severity", 0) or 0
                    )
                except (TypeError, ValueError):
                    msg_score = 0.0

                # Prefer the total transaction anomaly score over the per-rule severity
                anomaly_score = float(tx_anomaly_score) if tx_anomaly_score else msg_score

                matches.append({
                    "tx_id":          tx_id,
                    "timestamp":      original_entry.get("timestamp", ""),
                    "client_ip":      original_entry.get("client_ip", ""),
                    "method":         original_entry.get("http_method", ""),
                    "uri":            original_entry.get("request_path", ""),
                    "rule_id":        rule_id,
                    "message":        message,
                    "anomaly_score":  anomaly_score,
                    "tags":           json.dumps(tags),
                    "paranoia_level": paranoia_level,
                    "original_entry": original_entry,
                })

    logger.info(
        f"[CRS] Parsed audit log: {lines_read} lines read, "
        f"{lines_error} parse errors, {len(matches)} rule matches found"
    )
    return matches


# ── Public API ─────────────────────────────────────────────────────────────────

def run_crs_detection(
    normalized_path: "Path | str",
    run_id: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts:   Optional[str] = None,
) -> list[dict]:
    """Run CRS detection by replaying normalised log entries.

    Args:
        normalized_path: Path to normalized_logs.json.
        run_id:          Optional pipeline run ID for SQLite linkage.
        start_ts / end_ts: Optional ISO 8601 time range filter (matches the
                           same convention used by run_rule_pipeline_from_file).

    Returns:
        List of CRS match dicts (empty list if service unavailable or no hits).
        Each dict has keys: tx_id, timestamp, client_ip, method, uri, rule_id,
        message, anomaly_score, tags (JSON string), paranoia_level,
        original_entry (full log dict).
    """
    normalized_path = Path(normalized_path)

    # ── Availability check ─────────────────────────────────────────────────────
    if not check_crs_available():
        logger.warning(
            "[CRS] Skipped — crs-detector service is not reachable at "
            f"{CRS_SERVICE_URL}. "
            "Is 'docker compose up crs-detector' running? "
            "Pipeline continues without CRS results."
        )
        print("[CRS] SKIP — crs-detector unreachable (running outside Docker?)")
        return []

    if not normalized_path.exists():
        logger.error(f"[CRS] Normalised log file not found: {normalized_path}")
        return []

    print(f"[CRS] Starting CRS replay against {CRS_SERVICE_URL} …")
    logger.info(f"[CRS] Normalised log: {normalized_path} | audit log: {CRS_AUDIT_LOG}")

    session   = _build_session()
    all_tx_map: dict[str, dict] = {}
    batch:      list[dict]       = []
    total_entries = 0
    total_batches = 0

    # ── Record audit log offset BEFORE replay so we only parse new lines ───────
    audit_path = Path(CRS_AUDIT_LOG)
    audit_start_offset = audit_path.stat().st_size if audit_path.exists() else 0
    logger.info(f"[CRS] Audit log offset before replay: {audit_start_offset} bytes")

    # ── Stream and replay in batches ───────────────────────────────────────────
    with open(normalized_path, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            # Optional time-range filter (mirrors rule_pipeline.py behaviour)
            ts = entry.get("timestamp", "")
            if start_ts and ts and ts < start_ts:
                continue
            if end_ts and ts and ts > end_ts:
                continue

            batch.append(entry)
            total_entries += 1

            if len(batch) >= CRS_BATCH_SIZE:
                tx_map = _replay_entries(batch, session)
                all_tx_map.update(tx_map)
                total_batches += 1
                print(
                    f"[CRS]   Batch {total_batches}: replayed {len(batch)} entries "
                    f"({total_entries} total)"
                )
                batch = []

    # Flush remaining entries
    if batch:
        tx_map = _replay_entries(batch, session)
        all_tx_map.update(tx_map)
        total_batches += 1
        print(
            f"[CRS]   Batch {total_batches}: replayed {len(batch)} entries "
            f"({total_entries} total)"
        )

    if not all_tx_map:
        print("[CRS] No entries replayed.")
        return []

    print(
        f"[CRS] Replay complete: {total_entries} entries in {total_batches} batches. "
        f"Waiting {CRS_FLUSH_WAIT}s for audit log flush …"
    )

    # ── Wait for nginx/ModSecurity to flush the audit log ─────────────────────
    time.sleep(CRS_FLUSH_WAIT)

    # ── Parse only the NEW audit log lines written during this run ─────────────
    matches = _parse_audit_log(CRS_AUDIT_LOG, all_tx_map, start_offset=audit_start_offset)

    unique_rules = len({m["rule_id"] for m in matches})
    unique_ips   = len({m["client_ip"] for m in matches})

    print(
        f"[CRS] Detection complete:\n"
        f"[CRS]   Total matches   : {len(matches)}\n"
        f"[CRS]   Unique rules    : {unique_rules}\n"
        f"[CRS]   Unique IPs      : {unique_ips}\n"
        f"[CRS]   Paranoia level  : {os.getenv('CRS_PARANOIA_LEVEL', '1')}"
    )
    logger.info(
        f"[CRS] Detection complete: {len(matches)} matches, "
        f"{unique_rules} unique rules, {unique_ips} unique IPs"
    )

    return matches
