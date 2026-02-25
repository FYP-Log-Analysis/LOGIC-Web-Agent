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


def api_health() -> bool:
    try:
        r = requests.get(f"{API_BASE}/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def upload_file(file_bytes: bytes, filename: str) -> Dict:
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
    return _get(f"/api/upload/status/{upload_id}", timeout=10)


def get_log_time_range() -> Dict:
    return _get("/api/logs/time-range", timeout=10)


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
    return _get(f"/api/analysis/run/{run_id}", timeout=10)


def get_threat_insights() -> Dict:
    return _post("/api/analysis/threat-insights")


def get_insights_status() -> Dict:
    return _get("/api/analysis/threat-insights/status")


def get_pipeline_steps() -> Dict:
    return _get("/api/pipeline/steps")


def run_pipeline() -> Dict:
    return _post("/api/pipeline/run")


def run_pipeline_step(step_id: str) -> Dict:
    return _post(f"/api/pipeline/run/{step_id}")


# ── Behavioral analysis ───────────────────────────────────────────────────────

def run_behavioral_analysis(
    rate_window_minutes:    int   = 1,
    rate_threshold:         int   = 60,
    enum_window_hours:      int   = 1,
    enum_threshold:         int   = 50,
    status_window_minutes:  int   = 5,
    status_error_ratio:     float = 0.50,
    visitor_zscore:         float = 2.0,
    start_ts:               Optional[str] = None,
    end_ts:                 Optional[str] = None,
) -> Dict:
    """Trigger behavioral traffic analysis on the API server."""
    return _post("/api/analysis/behavioral", json={
        "rate_window_minutes":   rate_window_minutes,
        "rate_threshold":        rate_threshold,
        "enum_window_hours":     enum_window_hours,
        "enum_threshold":        enum_threshold,
        "status_window_minutes": status_window_minutes,
        "status_error_ratio":    status_error_ratio,
        "visitor_zscore":        visitor_zscore,
        "start_ts":              start_ts,
        "end_ts":                end_ts,
    })


def get_behavioral_results() -> Dict:
    """Fetch the latest behavioral analysis results from the API."""
    return _get("/api/analysis/behavioral/results")
