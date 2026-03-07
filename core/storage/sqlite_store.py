# Lightweight SQLite store for all detection results,
# pipeline run history, uploaded log entries, CRS match data, and behavioral alerts.
# Database lives at data/logic.db
import json
import sqlite3
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
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

            CREATE TABLE IF NOT EXISTS ip_geo (
                client_ip              TEXT PRIMARY KEY,
                country_code           TEXT,
                country_name           TEXT,
                is_private_or_unknown  INTEGER DEFAULT 0,
                lookup_source          TEXT,
                updated_at             TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ip_geo_country_code ON ip_geo(country_code);

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

            -- ── COMPACT BEHAVIORAL AGGREGATION TABLES ───────────────────────
            -- These replace row-by-row log insertion. The pipeline accumulates
            -- these aggregations in-memory during the streaming parse pass and
            -- writes them here in a single bulk transaction — orders of magnitude
            -- faster than inserting millions of raw log rows.

            CREATE TABLE IF NOT EXISTS log_summaries (
                upload_id        TEXT PRIMARY KEY,
                project_id       TEXT,
                total_count      INTEGER DEFAULT 0,
                min_ts           TEXT,
                max_ts           TEXT,
                unique_ip_count  INTEGER DEFAULT 0
            );

            -- Per-IP per-minute request counts (rate-spike detection)
            CREATE TABLE IF NOT EXISTS rate_spike_buckets (
                upload_id       TEXT NOT NULL,
                project_id      TEXT,
                client_ip       TEXT NOT NULL,
                window_minute   TEXT NOT NULL,
                request_count   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (upload_id, client_ip, window_minute)
            );
            CREATE INDEX IF NOT EXISTS idx_rsb_window ON rate_spike_buckets(window_minute);
            CREATE INDEX IF NOT EXISTS idx_rsb_count  ON rate_spike_buckets(request_count);

            -- Per-IP per-hour distinct path counts (URL-enumeration detection)
            CREATE TABLE IF NOT EXISTS path_enum_buckets (
                upload_id       TEXT NOT NULL,
                project_id      TEXT,
                client_ip       TEXT NOT NULL,
                window_hour     TEXT NOT NULL,
                distinct_paths  INTEGER NOT NULL DEFAULT 0,
                total_requests  INTEGER NOT NULL DEFAULT 0,
                sample_paths    TEXT,
                PRIMARY KEY (upload_id, client_ip, window_hour)
            );
            CREATE INDEX IF NOT EXISTS idx_peb_distinct ON path_enum_buckets(distinct_paths);

            -- Per-minute status-code totals (status-spike detection)
            CREATE TABLE IF NOT EXISTS status_trend_buckets (
                upload_id        TEXT NOT NULL,
                project_id       TEXT,
                window_minute    TEXT NOT NULL,
                total_requests   INTEGER NOT NULL DEFAULT 0,
                error_count      INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (upload_id, window_minute)
            );

            -- Per-hour unique visitor + total request counts (visitor-anomaly detection)
            CREATE TABLE IF NOT EXISTS visitor_trend_buckets (
                upload_id        TEXT NOT NULL,
                project_id       TEXT,
                window_hour      TEXT NOT NULL,
                unique_visitors  INTEGER NOT NULL DEFAULT 0,
                total_requests   INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (upload_id, window_hour)
            );

            -- Per-IP summary stats (IP investigation page)
            CREATE TABLE IF NOT EXISTS ip_summaries (
                upload_id        TEXT NOT NULL,
                project_id       TEXT,
                client_ip        TEXT NOT NULL,
                request_count    INTEGER DEFAULT 0,
                unique_paths     INTEGER DEFAULT 0,
                first_seen       TEXT,
                last_seen        TEXT,
                top_ua_json      TEXT,
                status_dist_json TEXT,
                top_paths_json   TEXT,
                PRIMARY KEY (upload_id, client_ip)
            );
            CREATE INDEX IF NOT EXISTS idx_ips_client_ip ON ip_summaries(client_ip);
        """)

        # ── Non-destructive column migrations (project_id on existing tables) ──
        # SQLite ALTER TABLE ADD COLUMN succeeds silently; we guard with try/except
        # so re-running init_db on an existing database is always safe.
        _migrations = [
            "ALTER TABLE logs              ADD COLUMN project_id TEXT",
            "ALTER TABLE detections        ADD COLUMN project_id TEXT",
            "ALTER TABLE crs_matches       ADD COLUMN project_id TEXT",
            "ALTER TABLE behavioral_alerts ADD COLUMN project_id TEXT",
            "ALTER TABLE upload_status     ADD COLUMN project_id TEXT",
            "ALTER TABLE upload_status     ADD COLUMN filename    TEXT",
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


def query_logs(
    limit:      int = 5000,
    project_id: str | None = None,
) -> list[dict]:
    """Stream normalised log entries from the JSON file (avoids raw-log SQLite storage)."""
    import ijson

    candidates: list[Path] = []
    if project_id:
        p = PROJECT_ROOT / "data" / "projects" / project_id / "processed" / "normalized" / "normalized_logs.json"
        if p.exists():
            candidates.append(p)
    if not candidates:
        p = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
        if p.exists():
            candidates.append(p)
    if not candidates:
        return []

    results: list[dict] = []
    try:
        with open(candidates[0], "rb") as fh:
            for entry in ijson.items(fh, "item"):
                results.append(entry)
                if len(results) >= limit:
                    break
    except Exception as exc:
        logger.warning("query_logs: could not read %s: %s", candidates[0], exc)
    return results


def query_detections(
    severity:   str | None = None,
    rule_id:    str | None = None,
    client_ip:  str | None = None,
    project_id: str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    limit:      int = 500,
    offset:     int = 0,
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
    if project_id:
        conditions.append("project_id = ?")
        params.append(project_id)
    if start_ts:
        conditions.append("timestamp >= ?")
        params.append(start_ts)
    if end_ts:
        conditions.append("timestamp <= ?")
        params.append(end_ts)

    where  = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, offset]

    with _get_conn() as conn:
        rows = conn.execute(
            f"SELECT * FROM detections {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
    return [dict(r) for r in rows]


def _insert_ip_geo_rows(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    conn.executemany(
        """
        INSERT INTO ip_geo
            (client_ip, country_code, country_name, is_private_or_unknown, lookup_source, updated_at)
        VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
        ON CONFLICT(client_ip) DO UPDATE SET
            country_code = excluded.country_code,
            country_name = excluded.country_name,
            is_private_or_unknown = excluded.is_private_or_unknown,
            lookup_source = excluded.lookup_source,
            updated_at = excluded.updated_at
        """,
        rows,
    )


def upsert_ip_geo(client_ips: list[str]) -> int:
    if not client_ips:
        return 0

    from core.enrichment.geoip import lookup_ip_country

    unique_ips = sorted({ip.strip() for ip in client_ips if ip and ip.strip()})
    if not unique_ips:
        return 0

    placeholders = ",".join(["?"] * len(unique_ips))
    with _get_conn() as conn:
        existing = {
            row[0]
            for row in conn.execute(
                f"SELECT client_ip FROM ip_geo WHERE client_ip IN ({placeholders})",
                unique_ips,
            ).fetchall()
        }
        missing = [ip for ip in unique_ips if ip not in existing]
        if not missing:
            return 0

        rows = []
        for client_ip in missing:
            geo = lookup_ip_country(client_ip)
            rows.append(
                (
                    client_ip,
                    geo.get("country_code"),
                    geo.get("country_name"),
                    1 if geo.get("is_private_or_unknown") else 0,
                    geo.get("lookup_source"),
                )
            )
        _insert_ip_geo_rows(conn, rows)
    logger.info("Upserted %d GeoIP records", len(rows))
    return len(rows)


def ensure_ip_geo(client_ip: str | None) -> dict | None:
    if not client_ip:
        return None

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM ip_geo WHERE client_ip = ?",
            (client_ip,),
        ).fetchone()
        if row:
            return dict(row)

    upsert_ip_geo([client_ip])

    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM ip_geo WHERE client_ip = ?",
            (client_ip,),
        ).fetchone()
    return dict(row) if row else None


def backfill_ip_geo(limit: int = 5000) -> int:
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT client_ip
            FROM (
                SELECT client_ip FROM ip_summaries
                UNION
                SELECT client_ip FROM detections
                UNION
                SELECT client_ip FROM crs_matches
            ) src
            WHERE client_ip IS NOT NULL
              AND TRIM(client_ip) <> ''
              AND client_ip NOT IN (SELECT client_ip FROM ip_geo)
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return upsert_ip_geo([row[0] for row in rows])


def get_geo_summary(limit: int = 10, project_id: str | None = None) -> dict:
    backfilled = backfill_ip_geo()

    proj_filter = "WHERE d.project_id = ?" if project_id else ""
    proj_params = (project_id,) if project_id else ()

    with _get_conn() as conn:
        rows = conn.execute(
            f"""
            SELECT
                COALESCE(NULLIF(g.country_code, ''), 'ZZ') AS country_code,
                CASE
                    WHEN g.country_name IS NOT NULL AND g.country_name != '' THEN g.country_name
                    WHEN COALESCE(g.is_private_or_unknown, 1) = 1 THEN 'Private / Unknown'
                    ELSE 'Unknown'
                END AS country_name,
                COALESCE(g.is_private_or_unknown, 1) AS is_private_or_unknown,
                COUNT(*) AS detection_count,
                COUNT(DISTINCT d.client_ip) AS unique_ips,
                SUM(CASE WHEN LOWER(COALESCE(d.severity, '')) = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN LOWER(COALESCE(d.severity, '')) = 'high' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN LOWER(COALESCE(d.severity, '')) = 'medium' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN LOWER(COALESCE(d.severity, '')) = 'low' THEN 1 ELSE 0 END) AS low_count
            FROM detections d
            LEFT JOIN ip_geo g ON g.client_ip = d.client_ip
            {proj_filter}
            GROUP BY country_code, country_name, is_private_or_unknown
            ORDER BY detection_count DESC, country_name ASC
            """,
            proj_params,
        ).fetchall()

    countries = [dict(row) for row in rows]
    geolocated = [
        row for row in countries
        if row["country_code"] != "ZZ" and not row["is_private_or_unknown"]
    ]
    unknown = [row for row in countries if row["country_code"] == "ZZ" or row["is_private_or_unknown"]]

    total_detections = sum(row["detection_count"] for row in countries)
    geolocated_detections = sum(row["detection_count"] for row in geolocated)
    unknown_detections = sum(row["detection_count"] for row in unknown)
    top_country = geolocated[0] if geolocated else None
    coverage_pct = round((geolocated_detections / total_detections) * 100, 1) if total_detections else 0.0

    return {
        "countries_impacted": len(geolocated),
        "total_detections": total_detections,
        "geolocated_detections": geolocated_detections,
        "unknown_detections": unknown_detections,
        "coverage_pct": coverage_pct,
        "top_source_country": top_country,
        "countries": geolocated,
        "top_countries": geolocated[:limit],
        "backfilled_ip_count": backfilled,
    }


def get_stats(project_id: str | None = None) -> dict:
    proj_filter = "WHERE project_id = ?" if project_id else ""
    proj_params = (project_id,) if project_id else ()
    with _get_conn() as conn:
        total_det = conn.execute(
            f"SELECT COUNT(*) FROM detections {proj_filter}", proj_params
        ).fetchone()[0]
        by_severity = {
            row["severity"]: row["cnt"]
            for row in conn.execute(
                f"SELECT severity, COUNT(*) as cnt FROM detections {proj_filter} GROUP BY severity",
                proj_params,
            ).fetchall()
        }
        top_ips = [
            dict(r) for r in conn.execute(
                f"""
                SELECT client_ip, COUNT(*) as hit_count
                FROM detections
                {proj_filter}
                GROUP BY client_ip
                ORDER BY hit_count DESC
                LIMIT 10
                """,
                proj_params,
            ).fetchall()
        ]
    return {
        "total_detections":       total_det,
        "detections_by_severity": by_severity,
        "top_offending_ips":      top_ips,
    }


def get_ip_summary(client_ip: str) -> dict:
    """Return aggregated stats for a single IP from ip_summaries + detections tables."""
    geo = ensure_ip_geo(client_ip)
    with _get_conn() as conn:
        # Most-recent upload entry for this IP
        row = conn.execute(
            "SELECT * FROM ip_summaries WHERE client_ip = ? ORDER BY last_seen DESC LIMIT 1",
            (client_ip,),
        ).fetchone()

    if row and row["request_count"]:
        return {
            "client_ip":           client_ip,
            "country_code":        geo.get("country_code") if geo else None,
            "country_name":        geo.get("country_name") if geo else "Unknown",
            "request_count":       row["request_count"] or 0,
            "unique_paths":        row["unique_paths"] or 0,
            "first_seen":          row["first_seen"],
            "last_seen":           row["last_seen"],
            "user_agents":         json.loads(row["top_ua_json"] or "[]"),
            "status_distribution": json.loads(row["status_dist_json"] or "{}"),
            "top_paths":           json.loads(row["top_paths_json"] or "[]"),
        }

    # Fallback when no aggregation data exists for this IP
    return {
        "client_ip":           client_ip,
        "country_code":        geo.get("country_code") if geo else None,
        "country_name":        geo.get("country_name") if geo else "Unknown",
        "request_count":       0,
        "unique_paths":        0,
        "first_seen":          None,
        "last_seen":           None,
        "user_agents":         [],
        "status_distribution": {},
        "top_paths":           [],
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


def insert_behavioral_aggregations(
    upload_id:       str | None,
    project_id:      str | None,
    summary:         dict,
    rate_buckets:    dict,
    enum_buckets_c:  dict,
    enum_buckets_p:  dict,
    status_buckets:  dict,
    visitor_buckets: dict,
    hour_totals:     dict,
    ip_summaries:    dict,
) -> None:
    """Write compact behavioral aggregations to SQLite.

    Replaces bulk_insert_logs for the processing pipeline — writes lightweight
    pre-aggregated tables instead of millions of raw log rows.

    Args:
        summary:         {total_count, min_ts, max_ts, unique_ip_count}
        rate_buckets:    {(ip, min_bucket): count}
        enum_buckets_c:  {(ip, hour_bucket): total_requests}
        enum_buckets_p:  {(ip, hour_bucket): set(sample_paths, capped at 20)}
        status_buckets:  {min_bucket: [total, errors]}
        visitor_buckets: {hour_bucket: set(unique_ips)}
        hour_totals:     {hour_bucket: total_requests}
        ip_summaries:    {ip: {count, first_ts, last_ts, ua_ctr, status_ctr, path_ctr}}
    """
    uid = upload_id or ""

    with _get_conn() as conn:
        # 1. Log summary (one row per upload)
        conn.execute("DELETE FROM log_summaries WHERE upload_id = ?", (uid,))
        conn.execute(
            "INSERT INTO log_summaries (upload_id, project_id, total_count, min_ts, max_ts, unique_ip_count) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (uid, project_id, summary.get("total_count", 0),
             summary.get("min_ts"), summary.get("max_ts"),
             summary.get("unique_ip_count", 0)),
        )

        # 2. Rate spike buckets
        conn.execute("DELETE FROM rate_spike_buckets WHERE upload_id = ?", (uid,))
        if rate_buckets:
            conn.executemany(
                "INSERT INTO rate_spike_buckets (upload_id, project_id, client_ip, window_minute, request_count) "
                "VALUES (?, ?, ?, ?, ?)",
                [(uid, project_id, ip, min_bkt, cnt) for (ip, min_bkt), cnt in rate_buckets.items()],
            )

        # 3. Path enumeration buckets
        conn.execute("DELETE FROM path_enum_buckets WHERE upload_id = ?", (uid,))
        if enum_buckets_c:
            rows = []
            for (ip, hour_bkt), total_reqs in enum_buckets_c.items():
                sample = list(enum_buckets_p.get((ip, hour_bkt), set()))
                rows.append((uid, project_id, ip, hour_bkt, len(sample), total_reqs, json.dumps(sample)))
            conn.executemany(
                "INSERT INTO path_enum_buckets "
                "(upload_id, project_id, client_ip, window_hour, distinct_paths, total_requests, sample_paths) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

        # 4. Status trend buckets
        conn.execute("DELETE FROM status_trend_buckets WHERE upload_id = ?", (uid,))
        if status_buckets:
            conn.executemany(
                "INSERT INTO status_trend_buckets (upload_id, project_id, window_minute, total_requests, error_count) "
                "VALUES (?, ?, ?, ?, ?)",
                [(uid, project_id, min_bkt, totals[0], totals[1]) for min_bkt, totals in status_buckets.items()],
            )

        # 5. Visitor trend buckets
        conn.execute("DELETE FROM visitor_trend_buckets WHERE upload_id = ?", (uid,))
        if visitor_buckets:
            conn.executemany(
                "INSERT INTO visitor_trend_buckets (upload_id, project_id, window_hour, unique_visitors, total_requests) "
                "VALUES (?, ?, ?, ?, ?)",
                [(uid, project_id, hour, len(ip_set), hour_totals.get(hour, 0))
                 for hour, ip_set in visitor_buckets.items()],
            )

        # 6. IP summaries
        conn.execute("DELETE FROM ip_summaries WHERE upload_id = ?", (uid,))
        if ip_summaries:
            rows = []
            for ip, s in ip_summaries.items():
                top_ua   = [{"user_agent": ua, "count": c} for ua, c in s["ua_ctr"].most_common(5)]
                top_path = [{"request_path": p, "count": c} for p, c in s["path_ctr"].most_common(10)]
                rows.append((
                    uid, project_id, ip,
                    s["count"], len(s["path_ctr"]),
                    s["first_ts"], s["last_ts"],
                    json.dumps(top_ua),
                    json.dumps(dict(s["status_ctr"])),
                    json.dumps(top_path),
                ))
            conn.executemany(
                "INSERT INTO ip_summaries "
                "(upload_id, project_id, client_ip, request_count, unique_paths, "
                " first_seen, last_seen, top_ua_json, status_dist_json, top_paths_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    logger.info(
        "Behavioral aggregations written: %s entries, %s rate buckets, %s IPs",
        summary.get("total_count", 0), len(rate_buckets), len(ip_summaries),
    )


def get_log_time_range(project_id: str | None = None) -> dict:
    with _get_conn() as conn:
        if project_id:
            row = conn.execute(
                "SELECT MIN(min_ts) AS min_ts, MAX(max_ts) AS max_ts, SUM(total_count) AS total "
                "FROM log_summaries WHERE project_id = ?",
                (project_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT MIN(min_ts) AS min_ts, MAX(max_ts) AS max_ts, SUM(total_count) AS total "
                "FROM log_summaries"
            ).fetchone()
    return {
        "min_timestamp": row["min_ts"] if row else None,
        "max_timestamp": row["max_ts"] if row else None,
        "total_logs":    row["total"] or 0 if row else 0,
    }


def get_log_count() -> int:
    with _get_conn() as conn:
        row = conn.execute("SELECT SUM(total_count) FROM log_summaries").fetchone()
        return row[0] or 0


def insert_upload_status(
    upload_id:  str,
    project_id: str | None = None,
    filename:   str | None = None,
) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO upload_status (upload_id, project_id, filename, stage, status) "
            "VALUES (?, ?, ?, 'uploading', 'running')",
            (upload_id, project_id, filename),
        )


def get_uploads_for_project(project_id: str) -> list[dict]:
    """Return all upload records for a given project, newest first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT upload_id, filename, stage, status, entry_count, started_at, updated_at "
            "FROM upload_status WHERE project_id = ? ORDER BY started_at DESC",
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


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
    project_id: str | None = None,
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    limit:      int = 1000,
    offset:     int = 0,
) -> list[dict]:
    """Fetch behavioral alerts with optional type/IP/project/time filter."""
    conditions, params = [], []
    if alert_type:
        conditions.append("alert_type = ?")
        params.append(alert_type)
    if client_ip:
        conditions.append("client_ip = ?")
        params.append(client_ip)
    if project_id:
        conditions.append("project_id = ?")
        params.append(project_id)
    if start_ts:
        conditions.append("created_at >= ?")
        params.append(start_ts)
    if end_ts:
        conditions.append("created_at <= ?")
        params.append(end_ts)
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
        "logs", "detections", "crs_matches",
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
    return {
        "log_entries": log_count,
        "detections":  det_count,
    }

