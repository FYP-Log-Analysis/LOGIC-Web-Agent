# Reads detection results and CRS matches from data/ for the dashboard to display.
# Uses ijson for large JSON files to avoid loading hundreds of MB into container RAM.
import json
import os
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional

import ijson  # streaming JSON parser — never loads multi-GB files into RAM

DATA_ROOT = Path(os.getenv("DATA_ROOT", "/app/data"))
_DB_PATH  = DATA_ROOT / "logic.db"   # CRS INTEGRATION: shared SQLite database

# Cap how many rows are streamed into dashboard memory.
# Large JSON files (100k+ rows) will OOM the container if fully loaded.
_ANOMALY_LIMIT = int(os.getenv("ANOMALY_DISPLAY_LIMIT", "5000"))
_LOG_DISPLAY_LIMIT = int(os.getenv("LOG_DISPLAY_LIMIT", "5000"))


def _load_json(rel_path: str) -> dict | list | None:
    target = DATA_ROOT / rel_path
    if not target.exists():
        return None
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _stream_json_array(rel_path: str, limit: int) -> List[Dict]:
    target = DATA_ROOT / rel_path
    if not target.exists():
        return []
    results: List[Dict] = []
    try:
        with open(target, "rb") as fh:
            for item in ijson.items(fh, "item"):
                results.append(item)
                if len(results) >= limit:
                    break
    except Exception:
        pass
    return results


def get_rule_matches() -> Dict:
    data = _load_json("detection_results/rule_matches.json")
    return data or {"matches": [], "matched_rules": [], "total_matches": 0}


def get_anomaly_scores() -> List[Dict]:
    # Stream only the first _ANOMALY_LIMIT rows — never load the full 800 MB+ file
    return _stream_json_array("detection_results/anomaly_scores.json", _ANOMALY_LIMIT)


def get_normalized_logs() -> List[Dict]:
    return _stream_json_array("processed/normalized/normalized_logs.json", _LOG_DISPLAY_LIMIT)


def get_behavioral_results() -> dict | None:
    """Load the latest behavioral_results.json produced by run_behavioral_analysis()."""
    return _load_json("detection_results/behavioral_results.json")


def get_data_sizes() -> List[Dict]:
    # Collect all raw log files dynamically (may be more than one)
    raw_logs_dir = DATA_ROOT / "raw_logs"
    raw_log_files = sorted(raw_logs_dir.glob("*")) if raw_logs_dir.exists() else []
    raw_tracked = [
        (f"Raw Log — {f.name}", f"raw_logs/{f.name}")
        for f in raw_log_files if f.is_file()
    ]

    static_tracked = [
        ("Normalised Logs (JSON)",   "processed/normalized/normalized_logs.json"),
        ("Rule Matches",             "detection_results/rule_matches.json"),
        ("Anomaly Scores",           "detection_results/anomaly_scores.json"),
        ("Raw Entries (ingestion)",  "intermediate/raw_entries.json"),
    ]
    tracked = raw_tracked + static_tracked
    results = []
    for label, rel in tracked:
        path = DATA_ROOT / rel
        if path.exists():
            bytes_ = path.stat().st_size
            if bytes_ >= 1_073_741_824:
                human = f"{bytes_ / 1_073_741_824:.2f} GB"
            elif bytes_ >= 1_048_576:
                human = f"{bytes_ / 1_048_576:.1f} MB"
            elif bytes_ >= 1_024:
                human = f"{bytes_ / 1_024:.1f} KB"
            else:
                human = f"{bytes_} B"
            results.append({"File": label, "Path": str(path.relative_to(DATA_ROOT)), "Size": human, "bytes": bytes_})
        else:
            results.append({"File": label, "Path": rel, "Size": "—", "bytes": 0})
    return results


# These functions query the crs_matches table in the shared SQLite database.
# The dashboard mounts ./data as /app/data (read-only), so we open the DB
# in WAL mode to allow safe concurrent reads while the API writes.

def _get_db_conn() -> sqlite3.Connection | None:
    db = DATA_ROOT / "logic.db"
    if not db.exists():
        return None
    try:
        # file URI with mode=ro — no write access needed, no WAL file created
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        # Fallback: plain read-write connection (works outside Docker)
        try:
            conn = sqlite3.connect(str(db))
            conn.row_factory = sqlite3.Row
            return conn
        except Exception:
            return None


def get_crs_matches(
    client_ip:  Optional[str]   = None,
    rule_id:    Optional[str]   = None,
    min_score:  Optional[float] = None,
    limit:      int             = 5000,
) -> List[Dict]:
    """Fetch CRS match rows from SQLite with optional filters.

    Returns an empty list if the database or crs_matches table doesn't exist
    yet (e.g., CRS has never been run).
    """
    conn = _get_db_conn()
    if conn is None:
        return []
    try:
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
        params.append(limit)

        rows = conn.execute(
            f"SELECT * FROM crs_matches {where} "
            f"ORDER BY anomaly_score DESC, id DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
    finally:
        conn.close()


def get_crs_stats() -> Dict:
    conn = _get_db_conn()
    if conn is None:
        return {
            "total_crs_matches": 0, "unique_crs_rules": 0,
            "unique_crs_ips": 0,   "max_anomaly_score": 0.0,
            "top_crs_rules": [],   "top_crs_ips": [],
        }
    try:
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
        max_score = float(max_score_row[0]) if max_score_row[0] is not None else 0.0

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
    except Exception:
        return {
            "total_crs_matches": 0, "unique_crs_rules": 0,
            "unique_crs_ips": 0,   "max_anomaly_score": 0.0,
            "top_crs_rules": [],   "top_crs_ips": [],
        }
    finally:
        conn.close()
