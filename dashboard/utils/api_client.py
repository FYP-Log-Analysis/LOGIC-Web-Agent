import json
import os
import requests
import streamlit as st
from typing import Dict, Any, Iterator, List, Optional

API_BASE = os.getenv("API_BASE_URL", "http://localhost:4000")
TIMEOUT  = 120  # seconds — reduced from 300; long-running ops use explicit timeouts


def _auth_header() -> Dict[str, str]:
    """Return Authorization header if the user is logged in."""
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _handle_401() -> None:
    """Clear session and force re-login when the token is expired or invalid."""
    for _k in ["authenticated", "token", "username", "role", "user_id", "email",
               "active_project_id", "active_project_name", "page"]:
        st.session_state.pop(_k, None)
    st.rerun()


def _http_err_detail(exc: requests.HTTPError) -> Dict:
    """Extract the FastAPI detail string from an HTTPError response body."""
    try:
        return {"error": exc.response.json().get("detail", str(exc))}
    except Exception:
        return {"error": str(exc)}


def _get(endpoint: str, timeout: int = TIMEOUT) -> Dict:
    try:
        r = requests.get(f"{API_BASE}{endpoint}", headers=_auth_header(), timeout=timeout)
        if r.status_code == 401:
            _handle_401()
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        return _http_err_detail(exc)
    except Exception as exc:
        return {"error": str(exc)}


def _post(endpoint: str, json: Any = None, files: Any = None, data: Any = None, timeout: int = TIMEOUT) -> Dict:
    try:
        if files:
            r = requests.post(f"{API_BASE}{endpoint}", files=files, data=data,
                              headers=_auth_header(), timeout=timeout)
        else:
            r = requests.post(f"{API_BASE}{endpoint}", json=json,
                              headers=_auth_header(), timeout=timeout)
        if r.status_code == 401:
            _handle_401()
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        return _http_err_detail(exc)
    except Exception as exc:
        return {"error": str(exc)}


def _delete(endpoint: str, timeout: int = TIMEOUT) -> Dict:
    try:
        r = requests.delete(f"{API_BASE}{endpoint}", headers=_auth_header(), timeout=timeout)
        if r.status_code == 401:
            _handle_401()
        r.raise_for_status()
        if r.status_code == 204 or not r.content:
            return {"ok": True}
        return r.json()
    except requests.HTTPError as exc:
        return _http_err_detail(exc)
    except Exception as exc:
        return {"error": str(exc)}


def api_health() -> bool:
    try:
        r = requests.get(f"{API_BASE}/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ── Auth ──────────────────────────────────────────────────────────────────────

def login(username: str, password: str) -> Dict:
    """Returns {access_token, token_type} or {error}."""
    try:
        r = requests.post(
            f"{API_BASE}/api/auth/login",
            data={"username": username, "password": password},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        try:
            return {"error": exc.response.json().get("detail", str(exc))}
        except Exception:
            return {"error": str(exc)}
    except Exception as exc:
        return {"error": str(exc)}


def register(username: str, email: str, password: str) -> Dict:
    return _post("/api/auth/register", json={
        "username": username,
        "email":    email,
        "password": password,
    })


def get_current_user() -> Dict:
    return _get("/api/auth/me", timeout=10)


# ── Projects ──────────────────────────────────────────────────────────────────

def create_project(name: str, description: str = "") -> Dict:
    return _post("/api/projects", json={"name": name, "description": description})


def get_projects() -> List[Dict]:
    result = _get("/api/projects", timeout=10)
    if isinstance(result, list):
        return result
    return result.get("projects", []) if isinstance(result, dict) and "projects" in result else []


def get_project_stats(project_id: str) -> Dict:
    return _get(f"/api/projects/{project_id}/stats", timeout=10)


def delete_project(project_id: str) -> Dict:
    return _delete(f"/api/projects/{project_id}")


# ── Admin ─────────────────────────────────────────────────────────────────────

def admin_list_users() -> List[Dict]:
    result = _get("/api/admin/users", timeout=10)
    return result if isinstance(result, list) else []


def admin_set_user_active(user_id: int, active: bool) -> Dict:
    action = "activate" if active else "deactivate"
    return _post(f"/api/admin/users/{user_id}/{action}")


def admin_delete_user(user_id: int) -> Dict:
    return _delete(f"/api/admin/users/{user_id}")


def admin_create_analyst(username: str, password: str) -> Dict:
    """Create a new analyst account via the register endpoint."""
    return _post("/api/auth/register", json={
        "username": username,
        "email":    f"{username}@logic.local",
        "password": password,
    })


def admin_stats() -> Dict:
    return _get("/api/admin/stats", timeout=10)


def upload_file(file_bytes: bytes, filename: str, project_id: str | None = None) -> Dict:
    try:
        files  = {"file": (filename, file_bytes, "application/octet-stream")}
        data   = {"project_id": project_id} if project_id else {}
        r = requests.post(
            f"{API_BASE}/api/upload",
            files=files,
            data=data,
            headers=_auth_header(),
            timeout=120,
        )
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as exc:
        try:
            return {"error": exc.response.json().get("detail", str(exc))}
        except Exception:
            return {"error": str(exc)}
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


# ── Hawkins AI chat ───────────────────────────────────────────────────────────

def stream_chat_message(
    context:  str,
    messages: List[Dict],
    timeout:  int = 60,
) -> Iterator[str]:
    """
    POST to /api/analysis/chat and yield raw text chunks as they arrive.

    The generator yields each chunk string.  On network or HTTP error it
    yields a single JSON error chunk  {"error": "..."}  so the caller
    can display a graceful message without raising an exception.

    Parameters
    ----------
    context  : rich component context string built by _build_context()
    messages : full conversation history [{role, content}, ...]
    timeout  : seconds before the streaming connection is abandoned
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

