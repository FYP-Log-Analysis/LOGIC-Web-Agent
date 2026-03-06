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

PROJECT_ROOT = Path(__file__).resolve().parents[2]
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
    """Return True if any compact-aggregation data is present (replaces logs table check)."""
    try:
        cnt = conn.execute("SELECT COUNT(*) FROM log_summaries").fetchone()[0]
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

    Queries the compact rate_spike_buckets table (written by the streaming parser)
    instead of the raw logs table. For window_minutes > 1, per-minute rows are
    aggregated in SQL.
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        conditions, params = [], []
        if start_ts:
            conditions.append("window_minute >= ?")
            params.append(start_ts[:16])
        if end_ts:
            conditions.append("window_minute <= ?")
            params.append(end_ts[:16])
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        if window_minutes == 1:
            # Direct query — each row is already one minute
            sql = f"""
                SELECT client_ip, window_minute AS window_start, request_count
                FROM rate_spike_buckets
                {where}
                HAVING request_count >= ?
                ORDER BY request_count DESC
                LIMIT 500
            """
            params.append(threshold)
        else:
            # Aggregate per-minute rows into wider windows
            bucket_sql = (
                f"strftime('%Y-%m-%dT%H:', window_minute) || "
                f"printf('%02d', (CAST(strftime('%M', window_minute) AS INTEGER) / {window_minutes}) * {window_minutes})"
            )
            sql = f"""
                SELECT client_ip,
                       {bucket_sql} AS window_start,
                       SUM(request_count) AS request_count
                FROM rate_spike_buckets
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

    Queries the compact path_enum_buckets table.
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        conditions, params = [], []
        if start_ts:
            conditions.append("window_hour >= ?")
            params.append(start_ts[:13] + ":00")
        if end_ts:
            conditions.append("window_hour <= ?")
            params.append(end_ts[:13] + ":00")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        if window_hours == 1:
            sql = f"""
                SELECT client_ip, window_hour AS window_start,
                       distinct_paths, total_requests, sample_paths
                FROM path_enum_buckets
                {where}
                HAVING distinct_paths >= ?
                ORDER BY distinct_paths DESC
                LIMIT 500
            """
            params.append(threshold)
        else:
            # Aggregate per-hour rows into wider windows (distinct_paths is approximate)
            bucket_sql = (
                f"strftime('%Y-%m-%dT', window_hour) || "
                f"printf('%02d:00', (CAST(strftime('%H', window_hour) AS INTEGER) / {window_hours}) * {window_hours})"
            )
            sql = f"""
                SELECT client_ip,
                       {bucket_sql} AS window_start,
                       SUM(distinct_paths) AS distinct_paths,
                       SUM(total_requests) AS total_requests,
                       NULL AS sample_paths
                FROM path_enum_buckets
                {where}
                GROUP BY client_ip, window_start
                HAVING distinct_paths >= ?
                ORDER BY distinct_paths DESC
                LIMIT 500
            """
            params.append(threshold)

        rows = conn.execute(sql, params).fetchall()
        import json as _json
        results = []
        for r in rows:
            try:
                samples = _json.loads(r["sample_paths"]) if r["sample_paths"] else []
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

    Queries the compact status_trend_buckets table.
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        conditions, params = [], []
        if start_ts:
            conditions.append("window_minute >= ?")
            params.append(start_ts[:16])
        if end_ts:
            conditions.append("window_minute <= ?")
            params.append(end_ts[:16])
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        if window_minutes == 1:
            sql = f"""
                SELECT window_minute AS window_start, total_requests, error_count,
                       CAST(error_count AS REAL) / total_requests AS error_ratio
                FROM status_trend_buckets
                {where}
                HAVING error_ratio >= ? AND total_requests >= 5
                ORDER BY error_ratio DESC, total_requests DESC
                LIMIT 500
            """
            params.append(error_ratio_threshold)
        else:
            bucket_sql = (
                f"strftime('%Y-%m-%dT%H:', window_minute) || "
                f"printf('%02d', (CAST(strftime('%M', window_minute) AS INTEGER) / {window_minutes}) * {window_minutes})"
            )
            sql = f"""
                SELECT {bucket_sql} AS window_start,
                       SUM(total_requests) AS total_requests,
                       SUM(error_count)    AS error_count,
                       CAST(SUM(error_count) AS REAL) / SUM(total_requests) AS error_ratio
                FROM status_trend_buckets
                {where}
                GROUP BY window_start
                HAVING error_ratio >= ? AND total_requests >= 5
                ORDER BY error_ratio DESC, total_requests DESC
                LIMIT 500
            """
            params.append(error_ratio_threshold)

        rows = conn.execute(sql, params).fetchall()
        return [
            {
                "window_start":     r["window_start"],
                "total_requests":   r["total_requests"],
                "error_count":      r["error_count"],
                "error_ratio":      round(float(r["error_ratio"]), 4),
                "top_status_codes": {},   # not stored at this granularity
                "threshold_used":   error_ratio_threshold,
                "window_minutes":   window_minutes,
            }
            for r in rows
        ]
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

    Queries the compact visitor_trend_buckets table.
    """
    conn = _get_conn()
    if conn is None:
        return []
    try:
        if not _logs_exist(conn):
            return []

        conditions, params = [], []
        if start_ts:
            conditions.append("window_hour >= ?")
            params.append(start_ts[:13] + ":00")
        if end_ts:
            conditions.append("window_hour <= ?")
            params.append(end_ts[:13] + ":00")
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT window_hour AS hour, unique_visitors, total_requests
            FROM visitor_trend_buckets
            {where}
            ORDER BY hour
        """
        rows = conn.execute(sql, params).fetchall()
        if not rows:
            return []

        counts = [r["unique_visitors"] for r in rows]
        if len(counts) < 3:
            return [
                {
                    "hour":            r["hour"],
                    "unique_visitors": r["unique_visitors"],
                    "total_requests":  r["total_requests"],
                    "mean_visitors":   None,
                    "std_visitors":    None,
                    "z_score":         None,
                    "flag":            "insufficient_data",
                }
                for r in rows
            ]

        mean_v = statistics.mean(counts)
        std_v  = statistics.pstdev(counts)

        results = []
        for r in rows:
            z    = (r["unique_visitors"] - mean_v) / std_v if std_v > 0 else 0.0
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
    from core.storage.sqlite_store import bulk_insert_behavioral_alerts

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
