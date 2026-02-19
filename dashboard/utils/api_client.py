"""
API Client — LOGIC Web Agent Dashboard
Thin wrapper for all API calls from the Streamlit frontend.
"""

import os
import requests
from typing import Dict, Any

API_BASE = os.getenv("API_BASE_URL", "http://localhost:4000")
TIMEOUT  = 300  # seconds — pipeline runs can be slow


def _get(endpoint: str) -> Dict:
    try:
        r = requests.get(f"{API_BASE}{endpoint}", timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


def _post(endpoint: str, json: Any = None) -> Dict:
    try:
        r = requests.post(f"{API_BASE}{endpoint}", json=json, timeout=TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}


# ── Pipeline ──────────────────────────────────────────────────────────────────
def get_pipeline_steps() -> Dict:
    return _get("/api/pipeline/steps")


def run_pipeline() -> Dict:
    return _post("/api/pipeline/run")


def run_pipeline_step(step_id: str) -> Dict:
    return _post(f"/api/pipeline/run/{step_id}")


# ── Analysis (Groq) ───────────────────────────────────────────────────────────
def get_threat_insights() -> Dict:
    return _post("/api/analysis/threat-insights")


def get_insights_status() -> Dict:
    return _get("/api/analysis/threat-insights/status")


# ── LM Studio ─────────────────────────────────────────────────────────────────
def get_lm_studio_status() -> Dict:
    """Check if LM Studio is reachable and return configuration info."""
    return _get("/api/analysis/lm-studio/status")


def get_lm_studio_insights() -> Dict:
    """Combined rule + anomaly analysis via local LM Studio."""
    return _post("/api/analysis/lm-studio/insights")


def get_lm_studio_anomaly_insights() -> Dict:
    """Anomaly-only natural language analysis via local LM Studio."""
    return _post("/api/analysis/lm-studio/anomaly-insights")


def get_lm_studio_rule_insights() -> Dict:
    """Rule-matches-only threat analysis via local LM Studio."""
    return _post("/api/analysis/lm-studio/rule-insights")


# ── Health ────────────────────────────────────────────────────────────────────
def api_health() -> bool:
    try:
        r = requests.get(f"{API_BASE}/", timeout=5)
        return r.status_code == 200
    except Exception:
        return False
