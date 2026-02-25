"""
Behavioral traffic analysis — detects volumetric & slow/low-volume attack patterns
by querying the normalized `logs` SQLite table.

Detections:
  1. Request-rate spikes   — high request count from a single IP in a short window
  2. URL enumeration       — single IP hitting many distinct paths (scanning)
  3. Status-code spikes    — time windows with an unusually high error (4xx/5xx) ratio
  4. Visitor-rate anomalies— hours where unique visitor count is statistically abnormal

All queries run entirely in SQLite using strftime() bucketing — no full table scans
into Python memory.
"""
from __future__ import annotations

import json
import logging
import math
import sqlite3
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data" / "logic.db"
RESULTS_PATH = PROJECT_ROOT / "data" / "detection_results" / "behavioral_results.json"

# ── Default thresholds ────────────────────────────────────────────────────────
RATE_WINDOW_MINUTES  = 1       # bucket width for per-IP rate analysis
RATE_THRESHOLD       = 60      # requests/window that triggers a spike alert
ENUM_WINDOW_HOURS    = 1       # bucket width for URL enumeration
ENUM_THRESHOLD       = 50      # distinct paths/hour that triggers enumeration alert
STATUS_WINDOW_MINUTES = 5      # bucket width for status-spike analysis
STATUS_ERROR_RATIO   = 0.50    # fraction of 4xx+5xx requests that triggers alert
VISITOR_ZSCORE       = 2.0     # z-score magnitude to flag visitor-rate anomaly


def _get_conn() -> sqlite3.Connection | None:
    if not DB_PATH.exists():
        logger.warning(f"Database not found at {DB_PATH}")
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _logs_exist(conn: sqlite3.Connection) -> bool:
    try:
        cnt = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        return cnt > 0
    except Exception:
        return False


# ── 1. Request-rate spikes ────────────────────────────────────────────────────

def compute_request_rate_spikes(
    window_minutes: int   = RATE_WINDOW_MINUTES,
    threshold:      int   = RATE_THRESHOLD,
    start_ts:       str | None = None,
    end_ts:         str | None = None,
) -> list[dict[str, Any]]:
    """Return per-IP time-buckets where request count exceeds *threshold*.

    Returns:
        list of dicts: client_ip, window_start, request_count, threshold_used
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        # SQLite strftime with minute rounding via integer arithmetic
        # bucket = YYYY-MM-DDTHH:MM rounded to window_minutes
        bucket_sql = (
            f"strftime('%Y-%m-%dT%H:', timestamp) || "
            f"printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / {window_minutes}) * {window_minutes})"
        )

        conditions, params = [], []
        if start_ts:
            conditions.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts:
            conditions.append("timestamp <= ?")
            params.append(end_ts)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT
                client_ip,
                {bucket_sql} AS window_start,
                COUNT(*) AS request_count
            FROM logs
            {where}
            GROUP BY client_ip, window_start
            HAVING request_count >= ?
            ORDER BY request_count DESC
            LIMIT 500
        """
        params.append(threshold)
        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "client_ip":      r["client_ip"],
                "window_start":   r["window_start"],
                "request_count":  r["request_count"],
                "threshold_used": threshold,
                "window_minutes": window_minutes,
            }
            for r in rows
        ]
    except Exception as exc:
        logger.error(f"compute_request_rate_spikes error: {exc}")
        return []
    finally:
        conn.close()


# ── 2. URL enumeration (scanning) ─────────────────────────────────────────────

def compute_url_enumeration(
    window_hours: int = ENUM_WINDOW_HOURS,
    threshold:    int = ENUM_THRESHOLD,
    start_ts:     str | None = None,
    end_ts:       str | None = None,
) -> list[dict[str, Any]]:
    """Detect IPs hitting an unusually large number of distinct URLs in a short window.

    Returns:
        list of dicts: client_ip, window_start, distinct_paths, total_requests, threshold_used
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        if window_hours == 1:
            bucket_sql = "strftime('%Y-%m-%dT%H:00', timestamp)"
        else:
            bucket_sql = (
                f"strftime('%Y-%m-%dT', timestamp) || "
                f"printf('%02d:00', (CAST(strftime('%H', timestamp) AS INTEGER) / {window_hours}) * {window_hours})"
            )

        conditions, params = [], []
        if start_ts:
            conditions.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts:
            conditions.append("timestamp <= ?")
            params.append(end_ts)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT
                client_ip,
                {bucket_sql} AS window_start,
                COUNT(DISTINCT COALESCE(path_clean, request_path)) AS distinct_paths,
                COUNT(*) AS total_requests
            FROM logs
            {where}
            GROUP BY client_ip, window_start
            HAVING distinct_paths >= ?
            ORDER BY distinct_paths DESC
            LIMIT 500
        """
        params.append(threshold)
        rows = conn.execute(sql, params).fetchall()

        # Fetch a sample of the scanned paths for context
        results = []
        for r in rows:
            sample_sql = (
                f"SELECT DISTINCT COALESCE(path_clean, request_path) AS p "
                f"FROM logs "
                f"WHERE client_ip = ? AND {bucket_sql} = ? "
                f"LIMIT 10"
            )
            try:
                samples = [s[0] for s in conn.execute(sample_sql, [r["client_ip"], r["window_start"]]).fetchall()]
            except Exception:
                samples = []
            results.append({
                "client_ip":       r["client_ip"],
                "window_start":    r["window_start"],
                "distinct_paths":  r["distinct_paths"],
                "total_requests":  r["total_requests"],
                "sample_paths":    samples,
                "threshold_used":  threshold,
                "window_hours":    window_hours,
            })
        return results
    except Exception as exc:
        logger.error(f"compute_url_enumeration error: {exc}")
        return []
    finally:
        conn.close()


# ── 3. Status-code spike windows ──────────────────────────────────────────────

def compute_status_code_spikes(
    window_minutes:        int   = STATUS_WINDOW_MINUTES,
    error_ratio_threshold: float = STATUS_ERROR_RATIO,
    start_ts:              str | None = None,
    end_ts:                str | None = None,
) -> list[dict[str, Any]]:
    """Find time windows where 4xx+5xx errors form a large fraction of traffic.

    Returns:
        list of dicts: window_start, total_requests, error_count, error_ratio, top_status_codes
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        bucket_sql = (
            f"strftime('%Y-%m-%dT%H:', timestamp) || "
            f"printf('%02d', (CAST(strftime('%M', timestamp) AS INTEGER) / {window_minutes}) * {window_minutes})"
        )

        conditions, params = [], []
        if start_ts:
            conditions.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts:
            conditions.append("timestamp <= ?")
            params.append(end_ts)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT
                {bucket_sql} AS window_start,
                COUNT(*) AS total_requests,
                SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
                CAST(SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS REAL) / COUNT(*) AS error_ratio
            FROM logs
            {where}
            GROUP BY window_start
            HAVING error_ratio >= ? AND total_requests >= 5
            ORDER BY error_ratio DESC, total_requests DESC
            LIMIT 500
        """
        params.append(error_ratio_threshold)
        rows = conn.execute(sql, params).fetchall()

        results = []
        for r in rows:
            # Get top 5 status codes in this window
            try:
                top_sc = conn.execute(
                    f"SELECT status_code, COUNT(*) AS cnt FROM logs "
                    f"WHERE {bucket_sql} = ? AND status_code >= 400 "
                    f"GROUP BY status_code ORDER BY cnt DESC LIMIT 5",
                    [r["window_start"]],
                ).fetchall()
                top_status = {str(x["status_code"]): x["cnt"] for x in top_sc}
            except Exception:
                top_status = {}
            results.append({
                "window_start":            r["window_start"],
                "total_requests":          r["total_requests"],
                "error_count":             r["error_count"],
                "error_ratio":             round(float(r["error_ratio"]), 4),
                "top_status_codes":        top_status,
                "threshold_used":          error_ratio_threshold,
                "window_minutes":          window_minutes,
            })
        return results
    except Exception as exc:
        logger.error(f"compute_status_code_spikes error: {exc}")
        return []
    finally:
        conn.close()


# ── 4. Visitor-rate anomalies ──────────────────────────────────────────────────

def compute_visitor_rate_anomalies(
    z_threshold: float = VISITOR_ZSCORE,
    start_ts:    str | None = None,
    end_ts:      str | None = None,
) -> list[dict[str, Any]]:
    """Flag hours where unique visitor count deviates significantly from the mean.

    Uses a simple z-score: flag when |z| >= z_threshold.

    Returns:
        list of dicts: hour, unique_visitors, mean_visitors, std_visitors, z_score, flag
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        conditions, params = [], []
        if start_ts:
            conditions.append("timestamp >= ?")
            params.append(start_ts)
        if end_ts:
            conditions.append("timestamp <= ?")
            params.append(end_ts)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT
                strftime('%Y-%m-%dT%H:00', timestamp) AS hour,
                COUNT(DISTINCT client_ip)              AS unique_visitors,
                COUNT(*)                               AS total_requests
            FROM logs
            {where}
            GROUP BY hour
            ORDER BY hour
        """
        rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []

        counts = [r["unique_visitors"] for r in rows]
        if len(counts) < 3:
            # Not enough data for meaningful z-score
            return [
                {
                    "hour":             r["hour"],
                    "unique_visitors":  r["unique_visitors"],
                    "total_requests":   r["total_requests"],
                    "mean_visitors":    None,
                    "std_visitors":     None,
                    "z_score":          None,
                    "flag":             "insufficient_data",
                }
                for r in rows
            ]

        mean_v = statistics.mean(counts)
        std_v  = statistics.pstdev(counts)  # population stdev

        results = []
        for r in rows:
            z = (r["unique_visitors"] - mean_v) / std_v if std_v > 0 else 0.0
            flag = "normal"
            if z >= z_threshold:
                flag = "high_visitor_rate"
            elif z <= -z_threshold:
                flag = "low_visitor_rate"
            results.append({
                "hour":            r["hour"],
                "unique_visitors": r["unique_visitors"],
                "total_requests":  r["total_requests"],
                "mean_visitors":   round(mean_v, 2),
                "std_visitors":    round(std_v, 2),
                "z_score":         round(z, 4),
                "flag":            flag,
            })
        return results
    except Exception as exc:
        logger.error(f"compute_visitor_rate_anomalies error: {exc}")
        return []
    finally:
        conn.close()


# ── Entry point ────────────────────────────────────────────────────────────────

def run_behavioral_analysis(
    rate_window_minutes:    int   = RATE_WINDOW_MINUTES,
    rate_threshold:         int   = RATE_THRESHOLD,
    enum_window_hours:      int   = ENUM_WINDOW_HOURS,
    enum_threshold:         int   = ENUM_THRESHOLD,
    status_window_minutes:  int   = STATUS_WINDOW_MINUTES,
    status_error_ratio:     float = STATUS_ERROR_RATIO,
    visitor_zscore:         float = VISITOR_ZSCORE,
    start_ts:               str | None = None,
    end_ts:                 str | None = None,
) -> dict[str, Any]:
    """Run all four behavioral detections, persist results, return summary dict."""

    logger.info("Starting behavioral analysis …")

    rate_spikes     = compute_request_rate_spikes(rate_window_minutes, rate_threshold, start_ts, end_ts)
    url_enum        = compute_url_enumeration(enum_window_hours, enum_threshold, start_ts, end_ts)
    status_spikes   = compute_status_code_spikes(status_window_minutes, status_error_ratio, start_ts, end_ts)
    visitor_rates   = compute_visitor_rate_anomalies(visitor_zscore, start_ts, end_ts)

    flagged_visitors = [v for v in visitor_rates if v.get("flag") not in ("normal", "insufficient_data")]

    result = {
        "generated_at":        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "start_ts":            start_ts,
        "end_ts":              end_ts,
        "thresholds": {
            "rate_window_minutes":   rate_window_minutes,
            "rate_threshold":        rate_threshold,
            "enum_window_hours":     enum_window_hours,
            "enum_threshold":        enum_threshold,
            "status_window_minutes": status_window_minutes,
            "status_error_ratio":    status_error_ratio,
            "visitor_zscore":        visitor_zscore,
        },
        "summary": {
            "total_rate_spike_windows":    len(rate_spikes),
            "total_enumeration_alerts":    len(url_enum),
            "total_status_spike_windows":  len(status_spikes),
            "total_visitor_anomaly_hours": len(flagged_visitors),
        },
        "request_rate_spikes": rate_spikes,
        "url_enumeration":     url_enum,
        "status_code_spikes":  status_spikes,
        "visitor_rates":       visitor_rates,
    }

    # Persist results JSON
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    logger.info(f"Behavioral results written to {RESULTS_PATH}")

    # Persist alerts to SQLite
    try:
        _persist_behavioral_alerts(result)
    except Exception as exc:
        logger.warning(f"Could not persist behavioral alerts to SQLite: {exc}")

    return result


def _persist_behavioral_alerts(result: dict) -> None:
    """Insert aggregated behavioral alerts into the behavioral_alerts SQLite table."""
    from analysis.sqlite_store import bulk_insert_behavioral_alerts

    alerts: list[dict] = []
    generated_at = result.get("generated_at", "")

    for item in result.get("request_rate_spikes", []):
        alerts.append({
            "run_id":       generated_at,
            "alert_type":   "request_rate_spike",
            "client_ip":    item.get("client_ip"),
            "window_start": item.get("window_start"),
            "value":        float(item.get("request_count", 0)),
            "threshold":    float(item.get("threshold_used", RATE_THRESHOLD)),
            "detail":       json.dumps({"window_minutes": item.get("window_minutes")}),
        })

    for item in result.get("url_enumeration", []):
        alerts.append({
            "run_id":       generated_at,
            "alert_type":   "url_enumeration",
            "client_ip":    item.get("client_ip"),
            "window_start": item.get("window_start"),
            "value":        float(item.get("distinct_paths", 0)),
            "threshold":    float(item.get("threshold_used", ENUM_THRESHOLD)),
            "detail":       json.dumps({
                "total_requests": item.get("total_requests"),
                "sample_paths":   item.get("sample_paths", []),
            }),
        })

    for item in result.get("status_code_spikes", []):
        alerts.append({
            "run_id":       generated_at,
            "alert_type":   "status_code_spike",
            "client_ip":    None,
            "window_start": item.get("window_start"),
            "value":        float(item.get("error_ratio", 0)),
            "threshold":    float(item.get("threshold_used", STATUS_ERROR_RATIO)),
            "detail":       json.dumps({
                "total_requests":   item.get("total_requests"),
                "error_count":      item.get("error_count"),
                "top_status_codes": item.get("top_status_codes"),
            }),
        })

    for item in result.get("visitor_rates", []):
        if item.get("flag") not in ("normal", "insufficient_data"):
            alerts.append({
                "run_id":       generated_at,
                "alert_type":   "visitor_rate_anomaly",
                "client_ip":    None,
                "window_start": item.get("hour"),
                "value":        float(item.get("unique_visitors", 0)),
                "threshold":    float(item.get("std_visitors") or 0),
                "detail":       json.dumps({
                    "z_score":       item.get("z_score"),
                    "flag":          item.get("flag"),
                    "mean_visitors": item.get("mean_visitors"),
                }),
            })

    if alerts:
        bulk_insert_behavioral_alerts(alerts)
