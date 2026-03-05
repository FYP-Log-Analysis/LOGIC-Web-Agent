"""
Base HTTP client helpers shared across all domain clients.

Domain-specific calls live in:
  auth_client.py     - login, register, get_current_user
  pipeline_client.py - get_pipeline_steps, run_pipeline, run_pipeline_step
  analysis_client.py - run_analysis, get_analysis_run, behavioral, chat, insights
  admin_client.py    - admin user/project management
  data_client.py     - upload_file, get_upload_status, projects CRUD
"""
import os
from typing import Any, Dict

import requests
import streamlit as st

API_BASE = os.getenv("API_BASE_URL", "http://localhost:4000")
TIMEOUT = 120  # seconds


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
    """Returns True if the API is reachable and healthy."""
    try:
        r = requests.get(f"{API_BASE}/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False

