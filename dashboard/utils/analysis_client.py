"""Analysis, behavioral, insights, and chat API calls."""
import json
from typing import Dict, Iterator, List, Optional

from utils.api_client import _get, _post, API_BASE, _auth_header
import requests


def run_analysis(
    mode:     str = "auto",
    start_ts: Optional[str] = None,
    end_ts:   Optional[str] = None,
) -> Dict:
    """Start CRS rule-based detection pipeline."""
    return _post("/api/analysis/run", json={
        "mode":     mode,
        "start_ts": start_ts,
        "end_ts":   end_ts,
    })


def get_analysis_run(run_id: str) -> Dict:
    return _get(f"/api/analysis/run/{run_id}", timeout=10)


def get_log_time_range() -> Dict:
    return _get("/api/logs/time-range", timeout=10)


def get_threat_insights() -> Dict:
    return _post("/api/analysis/threat-insights")


def get_insights_status() -> Dict:
    return _get("/api/analysis/threat-insights/status")


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


def stream_chat_message(
    context:  str,
    messages: List[Dict],
    timeout:  int = 60,
) -> Iterator[str]:
    """
    POST to /api/analysis/chat and yield raw text chunks as they arrive.
    Yields a single JSON error chunk {"error": "..."} on failure.
    """
    url = f"{API_BASE}/api/analysis/chat"
    payload = {
        "context":       context,
        "messages":      messages,
        "component_key": "dashboard",
    }
    try:
        with requests.post(url, json=payload, stream=True, timeout=timeout,
                           headers=_auth_header()) as resp:
            resp.raise_for_status()
            for chunk in resp.iter_content(chunk_size=None):
                if chunk:
                    yield chunk.decode("utf-8", errors="replace")
    except Exception as exc:
        yield json.dumps({"error": str(exc)})
