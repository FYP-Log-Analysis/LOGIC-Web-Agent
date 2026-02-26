# Lightweight SQLite store for all detection results, anomaly scores,
# pipeline run history, uploaded log entries, and CRS match data.
# Database lives at data/logic.db
import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data" / "logic.db"


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


def init_db() -> None:
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

            -- BEHAVIORAL ANALYSIS: volumetric / slow-attack detection alerts
            CREATE TABLE IF NOT EXISTS behavioral_alerts (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id       TEXT,
                alert_type   TEXT NOT NULL,   -- request_rate_spike | url_enumeration | status_code_spike | visitor_rate_anomaly
                client_ip    TEXT,            -- NULL for global (status/visitor) alerts
                window_start TEXT,
                value        REAL,            -- observed value (count / ratio / z-score)
                threshold    REAL,            -- threshold that was exceeded
                detail       TEXT,            -- JSON blob with extra context
                created_at   TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_beh_alert_type ON behavioral_alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_beh_client_ip  ON behavioral_alerts(client_ip);
            CREATE INDEX IF NOT EXISTS idx_beh_run_id     ON behavioral_alerts(run_id);

            -- ── AUTH: users ─────────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                username        TEXT    NOT NULL UNIQUE,
                email           TEXT    NOT NULL UNIQUE,
                hashed_password TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
                is_active       INTEGER NOT NULL DEFAULT 1,
                created_at      TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            -- ── AUTH: projects ───────────────────────────────────────────────
            CREATE TABLE IF NOT EXISTS projects (
                id          TEXT    PRIMARY KEY,   -- UUID
                name        TEXT    NOT NULL,
                description TEXT    DEFAULT '',
                owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at  TEXT    DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                last_run_at TEXT,
                status      TEXT    DEFAULT 'active'
            );

            CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner_id);
        """)

        # ── Non-destructive column migrations (project_id on existing tables) ──
        # SQLite ALTER TABLE ADD COLUMN succeeds silently; we guard with try/except
        # so re-running init_db on an existing database is always safe.
        _migrations = [
            "ALTER TABLE logs              ADD COLUMN project_id TEXT",
            "ALTER TABLE detections        ADD COLUMN project_id TEXT",
            "ALTER TABLE anomalies         ADD COLUMN project_id TEXT",
            "ALTER TABLE crs_matches       ADD COLUMN project_id TEXT",
            "ALTER TABLE behavioral_alerts ADD COLUMN project_id TEXT",
            "ALTER TABLE upload_status     ADD COLUMN project_id TEXT",
            "ALTER TABLE pipeline_runs     ADD COLUMN project_id TEXT",
        ]
        for stmt in _migrations:
            try:
                conn.execute(stmt)
            except Exception:
                pass  # column already exists — nothing to do

        # Indexes for the new project_id columns
        _idx = [
            "CREATE INDEX IF NOT EXISTS idx_logs_project_id  ON logs(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_det_project_id   ON detections(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_ano_project_id   ON anomalies(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_crs_project_id   ON crs_matches(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_beh_project_id   ON behavioral_alerts(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_upl_project_id   ON upload_status(project_id)",
            "CREATE INDEX IF NOT EXISTS idx_run_project_id   ON pipeline_runs(project_id)",
        ]
        for stmt in _idx:
            try:
                conn.execute(stmt)
            except Exception:
                pass

    logger.info(f"SQLite database initialised: {DB_PATH}")


def insert_detection(match: dict, run_id: str | None = None) -> None:
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


def bulk_insert_detections(matches: list[dict], run_id: str | None = None, project_id: str | None = None) -> int:
    if not matches:
        return 0
    rows = [
        (
            run_id,
            project_id,
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
                (run_id, project_id, rule_id, rule_title, severity, client_ip, timestamp,
                 method, path, status_code, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} detections into SQLite")
    return len(rows)


def bulk_insert_anomalies(entries: list[dict], run_id: str | None = None, project_id: str | None = None) -> int:
    if not entries:
        return 0
    rows = [
        (
            run_id,
            project_id,
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
                (run_id, project_id, client_ip, timestamp, method, path,
                 status_code, user_agent, anomaly_score, is_anomaly)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} anomaly scores into SQLite")
    return len(rows)


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


def insert_pipeline_run(run_id: str, source_file: str = "", file_size: int = 0) -> None:
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
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_pipeline_run(run_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return dict(row) if row else None


def bulk_insert_logs(entries: list[dict], upload_id: str | None = None, project_id: str | None = None) -> int:
    if not entries:
        return 0
    rows = [
        (
            upload_id,
            project_id,
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
                (upload_id, project_id, source, log_type, server_type, timestamp, client_ip,
                 auth_user, http_method, request_path, path_clean, query_string,
                 protocol, status_code, status_class, response_size, referer,
                 user_agent, is_bot, category, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} log entries into SQLite")
    return len(rows)


def get_log_time_range() -> dict:
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
    with _get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]


def insert_upload_status(upload_id: str) -> None:
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
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM upload_status WHERE upload_id = ?", (upload_id,)
        ).fetchone()
    return dict(row) if row else None


def bulk_insert_crs_matches(matches: list[dict], run_id: str | None = None, project_id: str | None = None) -> int:
    if not matches:
        return 0
    rows = [
        (
            run_id,
            project_id,
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
                (run_id, project_id, tx_id, timestamp, client_ip, method, uri,
                 rule_id, message, anomaly_score, tags, paranoia_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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


# ── Behavioral alerts ─────────────────────────────────────────────────────────

def bulk_insert_behavioral_alerts(alerts: list[dict], project_id: str | None = None) -> int:
    """Persist a batch of behavioral detection alerts."""
    if not alerts:
        return 0
    rows = [
        (
            a.get("run_id"),
            project_id,
            a.get("alert_type"),
            a.get("client_ip"),
            a.get("window_start"),
            a.get("value"),
            a.get("threshold"),
            a.get("detail"),
        )
        for a in alerts
    ]
    with _get_conn() as conn:
        conn.executemany("""
            INSERT INTO behavioral_alerts
                (run_id, project_id, alert_type, client_ip, window_start, value, threshold, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
    logger.info(f"Inserted {len(rows)} behavioral alerts into SQLite")
    return len(rows)


def get_behavioral_alerts(
    alert_type: str | None = None,
    client_ip:  str | None = None,
    limit:      int = 1000,
    offset:     int = 0,
) -> list[dict]:
    """Fetch behavioral alerts with optional type/IP filter."""
    conditions, params = [], []
    if alert_type:
        conditions.append("alert_type = ?")
        params.append(alert_type)
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM behavioral_alerts {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def get_behavioral_summary() -> dict:
    """Aggregate counts per alert_type from the latest behavioral run."""
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM behavioral_alerts").fetchone()[0]
        by_type = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT alert_type, COUNT(*) FROM behavioral_alerts GROUP BY alert_type"
            ).fetchall()
        }
        top_ips = [
            {"client_ip": r[0], "alert_count": r[1]}
            for r in conn.execute(
                "SELECT client_ip, COUNT(*) as cnt FROM behavioral_alerts "
                "WHERE client_ip IS NOT NULL "
                "GROUP BY client_ip ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        ]
    return {
        "total_behavioral_alerts": total,
        "by_type":                 by_type,
        "top_ips":                 top_ips,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Users
# ─────────────────────────────────────────────────────────────────────────────

def get_user_count() -> int:
    with _get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(
    username:        str,
    email:           str,
    hashed_password: str,
    role:            str = "user",
) -> dict:
    """Insert a new user and return the created row as a dict."""
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, email, hashed_password, role) VALUES (?, ?, ?, ?)",
            (username, email, hashed_password, role),
        )
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
    return dict(row)


def get_user_by_username(username: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, username, email, role, is_active, created_at "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def set_user_active(user_id: int, is_active: int) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id)
        )


def set_user_role(user_id: int, role: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )


def delete_user(user_id: int) -> None:
    with _get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# ─────────────────────────────────────────────────────────────────────────────
# Projects
# ─────────────────────────────────────────────────────────────────────────────

def create_project(project_id: str, name: str, description: str, owner_id: int) -> dict:
    """Create a project record and return it as a dict."""
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO projects (id, name, description, owner_id) VALUES (?, ?, ?, ?)",
            (project_id, name, description, owner_id),
        )
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
    return dict(row)


def get_project(project_id: str) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
    return dict(row) if row else None


def list_projects_for_user(owner_id: int) -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM projects WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_all_projects() -> list[dict]:
    """Admin view — all projects with owner username."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT p.*, u.username AS owner_username
               FROM projects p
               LEFT JOIN users u ON p.owner_id = u.id
               ORDER BY p.created_at DESC""",
        ).fetchall()
    return [dict(r) for r in rows]


def delete_project(project_id: str) -> None:
    """Delete a project and all its associated data rows."""
    tables = [
        "logs", "detections", "anomalies", "crs_matches",
        "behavioral_alerts", "upload_status", "pipeline_runs",
    ]
    with _get_conn() as conn:
        for table in tables:
            conn.execute(f"DELETE FROM {table} WHERE project_id = ?", (project_id,))
        conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))


def update_project_last_run(project_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE projects SET last_run_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') "
            "WHERE id = ?",
            (project_id,),
        )


def get_project_stats(project_id: str) -> dict:
    """Quick summary counts scoped to a project."""
    with _get_conn() as conn:
        log_count = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE project_id = ?", (project_id,)
        ).fetchone()[0]
        det_count = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE project_id = ?", (project_id,)
        ).fetchone()[0]
        ano_count = conn.execute(
            "SELECT COUNT(*) FROM anomalies WHERE project_id = ? AND is_anomaly = 1",
            (project_id,),
        ).fetchone()[0]
    return {
        "log_entries": log_count,
        "detections":  det_count,
        "anomalies":   ano_count,
    }

