"""
SQLite Store — LOGIC Web Agent
Lightweight persistent store for detections and anomaly scores.
Replaces the need for Elasticsearch at FYP scale.

Database file: data/logic.db
Tables:
  - detections   (rule-based matches from rule_pipeline)
  - anomalies    (ML scores from isolation_forest)
  - crs_matches  (CRS INTEGRATION: OWASP ModSecurity CRS matches)
"""

import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data" / "logic.db"


# ── Connection helper ──────────────────────────────────────────────────────────

@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row          # return dict-like rows
    conn.execute("PRAGMA journal_mode=WAL") # safe concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ─────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables and indices if they do not already exist."""
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS detections (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id      TEXT,
                rule_id     TEXT    NOT NULL,
                rule_title  TEXT,
                severity    TEXT,
                client_ip   TEXT,
                timestamp   TEXT,
                method      TEXT,
                path        TEXT,
                status_code INTEGER,
                user_agent  TEXT,
                created_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_det_severity   ON detections(severity);
            CREATE INDEX IF NOT EXISTS idx_det_rule_id    ON detections(rule_id);
            CREATE INDEX IF NOT EXISTS idx_det_client_ip  ON detections(client_ip);
            CREATE INDEX IF NOT EXISTS idx_det_timestamp  ON detections(timestamp);

            CREATE TABLE IF NOT EXISTS anomalies (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id        TEXT,
                client_ip     TEXT,
                timestamp     TEXT,
                method        TEXT,
                path          TEXT,
                status_code   INTEGER,
                user_agent    TEXT,
                anomaly_score REAL,
                is_anomaly    INTEGER,
                created_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ano_is_anomaly ON anomalies(is_anomaly);
            CREATE INDEX IF NOT EXISTS idx_ano_client_ip  ON anomalies(client_ip);
            CREATE INDEX IF NOT EXISTS idx_ano_timestamp  ON anomalies(timestamp);

            CREATE TABLE IF NOT EXISTS pipeline_runs (
                run_id      TEXT PRIMARY KEY,
                source_file TEXT,
                file_size   INTEGER,
                started_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                finished_at TEXT,
                status      TEXT DEFAULT 'pending',
                entries     INTEGER,
                detections  INTEGER,
                anomalies   INTEGER,
                error_msg   TEXT
            );

            CREATE TABLE IF NOT EXISTS logs (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                upload_id     TEXT,
                source        TEXT,
                log_type      TEXT,
                server_type   TEXT,
                timestamp     TEXT,
                client_ip     TEXT,
                auth_user     TEXT,
                http_method   TEXT,
                request_path  TEXT,
                path_clean    TEXT,
                query_string  TEXT,
                protocol      TEXT,
                status_code   INTEGER,
                status_class  TEXT,
                response_size INTEGER,
                referer       TEXT,
                user_agent    TEXT,
                is_bot        INTEGER,
                category      TEXT,
                raw           TEXT,
                created_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_logs_timestamp  ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_client_ip  ON logs(client_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_upload_id  ON logs(upload_id);

            CREATE TABLE IF NOT EXISTS upload_status (
                upload_id   TEXT PRIMARY KEY,
                stage       TEXT DEFAULT 'uploading',
                status      TEXT DEFAULT 'pending',
                entry_count INTEGER DEFAULT 0,
                error_msg   TEXT,
                started_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                updated_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            -- CRS INTEGRATION: OWASP ModSecurity CRS detection results
            CREATE TABLE IF NOT EXISTS crs_matches (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id          TEXT,
                tx_id           TEXT,
                timestamp       TEXT,
                client_ip       TEXT,
                method          TEXT,
                uri             TEXT,
                rule_id         TEXT,
                message         TEXT,
                anomaly_score   REAL    DEFAULT 0,
                tags            TEXT,   -- JSON array stored as text
                paranoia_level  INTEGER DEFAULT 1,
                created_at      TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_crs_rule_id       ON crs_matches(rule_id);
            CREATE INDEX IF NOT EXISTS idx_crs_client_ip     ON crs_matches(client_ip);
            CREATE INDEX IF NOT EXISTS idx_crs_timestamp     ON crs_matches(timestamp);
            CREATE INDEX IF NOT EXISTS idx_crs_anomaly_score ON crs_matches(anomaly_score);
        """)
    logger.info(f"SQLite database initialised: {DB_PATH}")


# ── Write helpers ──────────────────────────────────────────────────────────────

def insert_detection(match: dict, run_id: str | None = None) -> None:
    """Insert a single rule detection match."""
    with _get_conn() as conn:
        conn.execute("""
            INSERT INTO detections
                (run_id, rule_id, rule_title, severity, client_ip, timestamp,
                 method, path, status_code, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            run_id,
            match.get("rule_id"),
            match.get("rule_title"),
            match.get("severity"),
            match.get("client_ip"),
            match.get("timestamp"),
            match.get("method"),
            match.get("path"),
            match.get("status_code"),
            match.get("user_agent"),
        ))


def bulk_insert_detections(matches: list[dict], run_id: str | None = None) -> int:
    """Bulk insert detection matches — much faster than one-by-one for large sets."""
    if not matches:
        return 0
    rows = [
        (
            run_id,
            m.get("rule_id"),
            m.get("rule_title"),
            m.get("severity"),
            m.get("client_ip"),
            m.get("timestamp"),
            m.get("method"),
            m.get("path"),
            m.get("status_code"),
            m.get("user_agent"),
        )
        for m in matches
    ]
    with _get_conn() as conn:
        conn.executemany("""
            INSERT INTO detections
                (run_id, rule_id, rule_title, severity, client_ip, timestamp,
                 method, path, status_code, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} detections into SQLite")
    return len(rows)


def bulk_insert_anomalies(entries: list[dict], run_id: str | None = None) -> int:
    """Bulk insert anomaly scores."""
    if not entries:
        return 0
    rows = [
        (
            run_id,
            e.get("client_ip"),
            e.get("timestamp"),
            e.get("http_method") or e.get("method"),
            e.get("request_path") or e.get("path"),
            e.get("status_code"),
            e.get("user_agent"),
            e.get("anomaly_score"),
            1 if e.get("is_anomaly") else 0,
        )
        for e in entries
    ]
    with _get_conn() as conn:
        conn.executemany("""
            INSERT INTO anomalies
                (run_id, client_ip, timestamp, method, path,
                 status_code, user_agent, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} anomaly scores into SQLite")
    return len(rows)


# ── Read helpers ───────────────────────────────────────────────────────────────

def query_detections(
    severity:  str | None = None,
    rule_id:   str | None = None,
    client_ip: str | None = None,
    limit:     int = 500,
    offset:    int = 0,
) -> list[dict]:
    """Fetch detection rows with optional filters."""
    conditions, params = [], []
    if severity:
        conditions.append("LOWER(severity) = LOWER(?)")
        params.append(severity)
    if rule_id:
        conditions.append("rule_id = ?")
        params.append(rule_id)
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)

    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM detections {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def query_anomalies(
    only_anomalies: bool = True,
    client_ip:      str | None = None,
    limit:          int = 500,
    offset:         int = 0,
) -> list[dict]:
    """Fetch anomaly rows with optional filters."""
    conditions, params = [], []
    if only_anomalies:
        conditions.append("is_anomaly = 1")
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)

    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM anomalies {where} ORDER BY anomaly_score ASC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    """Return high-level counts for the Grafana SimpleJSON /query endpoint."""
    with _get_conn() as conn:
        total_det = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        by_severity = {
            row["severity"]: row["cnt"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM detections GROUP BY severity"
            ).fetchall()
        }
        total_processed = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
        flagged_ano = conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE is_anomaly = 1"
        ).fetchone()[0]
        top_ips = [
            dict(r) for r in conn.execute("""
                SELECT client_ip, COUNT(*) as hit_count
                FROM detections
                GROUP BY client_ip
                ORDER BY hit_count DESC
                LIMIT 10
            """).fetchall()
        ]
    return {
        "total_detections":           total_det,
        "detections_by_severity":     by_severity,
        "total_processed_entries":    total_processed,
        "anomaly_count":              flagged_ano,
        "top_offending_ips":          top_ips,
    }


# ── Pipeline runs ──────────────────────────────────────────────────────────────

def insert_pipeline_run(run_id: str, source_file: str = "", file_size: int = 0) -> None:
    """Create a new pipeline run record in 'pending' state."""
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO pipeline_runs (run_id, source_file, file_size, status) VALUES (?, ?, ?, 'pending')",
            (run_id, source_file, file_size),
        )


def update_pipeline_run(
    run_id: str,
    status: str,
    entries:    int | None = None,
    detections: int | None = None,
    anomalies:  int | None = None,
    error_msg:  str | None = None,
) -> None:
    """Update status and result counts for an existing pipeline run."""
    with _get_conn() as conn:
        conn.execute("""
            UPDATE pipeline_runs
               SET status      = ?,
                   finished_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                   entries     = COALESCE(?, entries),
                   detections  = COALESCE(?, detections),
                   anomalies   = COALESCE(?, anomalies),
                   error_msg   = COALESCE(?, error_msg)
             WHERE run_id = ?
        """, (status, entries, detections, anomalies, error_msg, run_id))


def get_pipeline_runs(limit: int = 50) -> list[dict]:
    """Return the most recent pipeline runs."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_pipeline_run(run_id: str) -> dict | None:
    """Return a single pipeline run by run_id."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


# ── Logs (normalised entries) ──────────────────────────────────────────────────

def bulk_insert_logs(entries: list[dict], upload_id: str | None = None) -> int:
    """Bulk insert normalised log entries into the logs table."""
    if not entries:
        return 0
    rows = [
        (
            upload_id,
            e.get("source"),
            e.get("log_type"),
            e.get("server_type"),
            e.get("timestamp"),
            e.get("client_ip"),
            e.get("auth_user"),
            e.get("http_method"),
            e.get("request_path"),
            e.get("path_clean"),
            e.get("query_string"),
            e.get("protocol"),
            e.get("status_code"),
            e.get("status_class"),
            e.get("response_size"),
            e.get("referer"),
            e.get("user_agent"),
            1 if e.get("is_bot") else 0,
            e.get("category"),
            e.get("raw"),
        )
        for e in entries
    ]
    with _get_conn() as conn:
        conn.executemany("""
            INSERT INTO logs
                (upload_id, source, log_type, server_type, timestamp, client_ip,
                 auth_user, http_method, request_path, path_clean, query_string,
                 protocol, status_code, status_class, response_size, referer,
                 user_agent, is_bot, category, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} log entries into SQLite")
    return len(rows)


def get_log_time_range() -> dict:
    """Return the earliest and latest timestamp stored in the logs table."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT MIN(timestamp) as min_ts, MAX(timestamp) as max_ts, COUNT(*) as total FROM logs"
        ).fetchone()
    return {
        "min_timestamp": row["min_ts"],
        "max_timestamp": row["max_ts"],
        "total_logs":    row["total"],
    }


def get_log_count() -> int:
    """Return total number of stored log entries."""
    with _get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]


# ── Upload status ──────────────────────────────────────────────────────────────

def insert_upload_status(upload_id: str) -> None:
    """Create an upload status record."""
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO upload_status (upload_id, stage, status) VALUES (?, 'uploading', 'running')",
            (upload_id,),
        )


def update_upload_status(
    upload_id:   str,
    stage:       str,
    status:      str,
    entry_count: int | None = None,
    error_msg:   str | None = None,
) -> None:
    """Update the current stage and status for an upload."""
    with _get_conn() as conn:
        conn.execute("""
            UPDATE upload_status
               SET stage       = ?,
                   status      = ?,
                   entry_count = COALESCE(?, entry_count),
                   error_msg   = COALESCE(?, error_msg),
                   updated_at  = strftime('%Y-%m-%dT%H:%M:%SZ','now')
             WHERE upload_id = ?
        """, (stage, status, entry_count, error_msg, upload_id))


def get_upload_status(upload_id: str) -> dict | None:
    """Return upload status record."""
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM upload_status WHERE upload_id = ?", (upload_id,)
        ).fetchone()
    return dict(row) if row else None


# ── CRS INTEGRATION: OWASP ModSecurity CRS helpers ─────────────────────────────

def bulk_insert_crs_matches(matches: list[dict], run_id: str | None = None) -> int:
    """Bulk insert OWASP CRS detection matches into the crs_matches table.

    Each dict in `matches` is expected to have keys produced by crs_processor.py:
    tx_id, timestamp, client_ip, method, uri, rule_id, message,
    anomaly_score, tags (JSON string), paranoia_level.
    """
    if not matches:
        return 0
    rows = [
        (
            run_id,
            m.get("tx_id"),
            m.get("timestamp"),
            m.get("client_ip"),
            m.get("method"),
            m.get("uri"),
            m.get("rule_id"),
            m.get("message"),
            m.get("anomaly_score", 0.0),
            m.get("tags", "[]"),
            m.get("paranoia_level", 1),
        )
        for m in matches
    ]
    with _get_conn() as conn:
        conn.executemany("""
            INSERT INTO crs_matches
                (run_id, tx_id, timestamp, client_ip, method, uri,
                 rule_id, message, anomaly_score, tags, paranoia_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"[CRS] Inserted {len(rows)} CRS matches into SQLite")
    return len(rows)


def query_crs_matches(
    client_ip:  str | None = None,
    rule_id:    str | None = None,
    min_score:  float | None = None,
    limit:      int = 500,
    offset:     int = 0,
) -> list[dict]:
    """Fetch CRS match rows with optional filters.

    Args:
        client_ip: Filter by source IP.
        rule_id:   Filter by CRS rule ID (exact match).
        min_score: Only rows with anomaly_score >= min_score.
        limit:     Maximum rows to return.
        offset:    Pagination offset.
    """
    conditions, params = [], []
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    if rule_id:
        conditions.append("rule_id = ?")
        params.append(rule_id)
    if min_score is not None:
        conditions.append("anomaly_score >= ?")
        params.append(min_score)

    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM crs_matches {where} "
            f"ORDER BY anomaly_score DESC, id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_crs_stats() -> dict:
    """Return high-level CRS detection counts for dashboard and API use."""
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM crs_matches").fetchone()[0]
        unique_rules = conn.execute(
            "SELECT COUNT(DISTINCT rule_id) FROM crs_matches"
        ).fetchone()[0]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT client_ip) FROM crs_matches"
        ).fetchone()[0]
        max_score_row = conn.execute(
            "SELECT MAX(anomaly_score) FROM crs_matches"
        ).fetchone()
        max_score = max_score_row[0] if max_score_row[0] is not None else 0.0

        top_rules = [
            dict(r) for r in conn.execute("""
                SELECT rule_id, message, COUNT(*) as hit_count
                FROM crs_matches
                GROUP BY rule_id
                ORDER BY hit_count DESC
                LIMIT 10
            """).fetchall()
        ]
        top_ips = [
            dict(r) for r in conn.execute("""
                SELECT client_ip, COUNT(*) as hit_count
                FROM crs_matches
                GROUP BY client_ip
                ORDER BY hit_count DESC
                LIMIT 10
            """).fetchall()
        ]
    return {
        "total_crs_matches":  total,
        "unique_crs_rules":   unique_rules,
        "unique_crs_ips":     unique_ips,
        "max_anomaly_score":  max_score,
        "top_crs_rules":      top_rules,
        "top_crs_ips":        top_ips,
    }

