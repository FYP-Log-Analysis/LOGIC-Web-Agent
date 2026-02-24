"""
API Client — LOGIC Web Agent Dashboard
Thin wrapper for all API calls from the Streamlit frontend.
"""

import os
import requests
from typing import Dict, Any, Optional

API_BASE = os.getenv("API_BASE_URL", "http://localhost:4000")
TIMEOUT  = 300  # seconds — pipeline runs can be slow


def _get(endpoint: str, timeout: int = TIMEOUT) -> Dict:
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def _post(endpoint: str, json: Any = None, files: Any = None, timeout: int = TIMEOUT) -> Dict:
    try:
        if files:
            r = requests.post(f"{API_BASE}{endpoint}", files=files, timeout=timeout)
        else:
            r = requests.post(f"{API_BASE}{endpoint}", json=json, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


# ── Health ────────────────────────────────────────────────────────────────────
def api_health() -> bool:
    try:
        r = requests.get(f"{API_BASE}/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ── Upload ────────────────────────────────────────────────────────────────────
def upload_file(file_bytes: bytes, filename: str) -> Dict:
    """Upload a log file and return upload_id for progress polling."""
    try:
        r = requests.post(
            f"{API_BASE}/api/upload",
            files={"file": (filename, file_bytes, "application/octet-stream")},
            timeout=120,
        )
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def get_upload_status(upload_id: str) -> Dict:
    """Poll upload/ingestion/normalisation progress."""
    return _get(f"/api/upload/status/{upload_id}", timeout=10)


# ── Log time range ────────────────────────────────────────────────────────────
def get_log_time_range() -> Dict:
    """Return min/max timestamp from the stored logs table."""
    return _get("/api/logs/time-range", timeout=10)


# ── On-demand analysis ────────────────────────────────────────────────────────
def run_analysis(
    mode:          str = "auto",
    start_ts:      Optional[str] = None,
    end_ts:        Optional[str] = None,
    analysis_type: str = "both",
) -> Dict:
    """Start analysis pipeline. analysis_type: 'both' | 'crs' | 'ml'."""
    return _post("/api/analysis/run", json={
        "mode":          mode,
        "start_ts":      start_ts,
        "end_ts":        end_ts,
        "analysis_type": analysis_type,
    })


def get_analysis_run(run_id: str) -> Dict:
    """Poll status of a running analysis."""
    return _get(f"/api/analysis/run/{run_id}", timeout=10)


# ── Analysis (Groq AI) ────────────────────────────────────────────────────────
def get_threat_insights() -> Dict:
    """Generate Groq AI threat analysis from rule detection results."""
    return _post("/api/analysis/threat-insights")


def get_insights_status() -> Dict:
    """Check whether detection results are available for AI analysis."""
    return _get("/api/analysis/threat-insights/status")


# ── Pipeline (kept for backward compatibility) ────────────────────────────────
def get_pipeline_steps() -> Dict:
    return _get("/api/pipeline/steps")


def run_pipeline() -> Dict:
    return _post("/api/pipeline/run")


def run_pipeline_step(step_id: str) -> Dict:
    return _post(f"/api/pipeline/run/{step_id}")
