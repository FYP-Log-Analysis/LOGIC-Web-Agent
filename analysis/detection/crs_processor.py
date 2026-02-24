# Replays normalised log entries against the OWASP ModSecurity CRS service and
# extracts rule match details from the JSON audit log.
#
# Flow: stream normalized_logs.json → send each entry to crs-detector via HTTP
# with a unique X-Logic-TxId header → wait for audit log flush → parse NDJSON.
#
# Reads env vars: CRS_SERVICE_URL, CRS_AUDIT_LOG, CRS_BATCH_SIZE, CRS_FLUSH_WAIT.
# Degrades gracefully when the crs-detector container is not running.

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

# Configuration — all values can be overridden via environment variables

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


# Build a retry-enabled session with a connection pool sized to the worker count
def _build_session() -> requests.Session:
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


# Send a HEAD request to check whether the crs-detector container is up before starting replay
def check_crs_available() -> bool:
    try:
        resp = requests.head(CRS_SERVICE_URL, timeout=3)
        return True  # any HTTP response = service is up
    except Exception:
        return False


# Converts a normalised log entry into the kwargs dict that session.request() expects
def _build_request(entry: dict, tx_id: str) -> dict:
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


# Sends all entries to the CRS service concurrently using a thread pool;
# returns a tx_id → original_entry mapping for audit log correlation
def _replay_entries(
    entries: list[dict],
    session: requests.Session,
) -> dict[str, dict]:
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


# Parses the ModSecurity NDJSON audit log and extracts CRS rule matches.
# start_offset lets us skip audit entries written before this replay started.
def _parse_audit_log(
    audit_path: str,
    tx_map: dict[str, dict],
    start_offset: int = 0,
) -> list[dict]:
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

            # Find our X-Logic-TxId header to match this audit entry back to the original request
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

            # Pull out the list of rules that fired for this transaction
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


def run_crs_detection(
    normalized_path: "Path | str",
    run_id: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts:   Optional[str] = None,
) -> list[dict]:
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

    # Record the current audit log size so we only parse lines written DURING this run
    audit_path = Path(CRS_AUDIT_LOG)
    audit_start_offset = audit_path.stat().st_size if audit_path.exists() else 0
    logger.info(f"[CRS] Audit log offset before replay: {audit_start_offset} bytes")

    # Stream the normalised log and replay in fixed-size batches to keep memory flat
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

    # Give nginx/ModSecurity time to finish writing the audit log before we read it
    time.sleep(CRS_FLUSH_WAIT)

    # Parse only the lines appended during this run — ignore anything pre-existing
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
