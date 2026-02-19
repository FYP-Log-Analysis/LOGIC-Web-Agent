"""
Analysis Routes — LOGIC Web Agent
LLM-powered threat intelligence endpoints.
Supports both Groq Cloud and local LM Studio backends.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict
from api.services.llm_service import (
    analyse_detection_results,
    analyse_specific_match,
    analyse_with_lm_studio,
    analyse_anomalies_with_lm_studio,
    lm_studio_reachable,
    LM_STUDIO_BASE_URL,
    LM_STUDIO_MODEL,
)
import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()

RESULTS_FILE  = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "rule_matches.json"
ANOMALY_FILE  = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "anomaly_scores.json"


def _load_results() -> Dict:
    if not RESULTS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No detection results found. Run the rule analysis pipeline first.",
        )
    with open(RESULTS_FILE, "r") as fh:
        return json.load(fh)


def _load_anomalies() -> list:
    if not ANOMALY_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No anomaly scores found. Run the ML pipeline step first.",
        )
    with open(ANOMALY_FILE, "r") as fh:
        data = json.load(fh)
    # anomaly_scores.json may be a list or {"scores": [...]}
    return data if isinstance(data, list) else data.get("scores", data.get("entries", []))


# ── Groq endpoints (unchanged) ─────────────────────────────────────────────────

@router.post("/threat-insights")
async def get_threat_insights() -> Dict:
    """Generate AI-powered threat analysis from rule detection results (Groq)."""
    detection_data = _load_results()
    result = analyse_detection_results(detection_data)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return {"status": "success", **result}


@router.post("/threat-insights/{rule_id}")
async def analyse_rule_match(rule_id: str) -> Dict:
    """Analyse a single detected rule match in detail (Groq)."""
    detection_data = _load_results()
    matches = detection_data.get("matches", [])
    match = next((m for m in matches if m.get("rule_id") == rule_id), None)
    if not match:
        raise HTTPException(status_code=404, detail=f"No match found for rule id '{rule_id}'")
    result = analyse_specific_match(match)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return {"status": "success", **result, "match_details": match}


@router.get("/threat-insights/status")
async def insights_status() -> Dict:
    """Check whether detection results are available."""
    if RESULTS_FILE.exists():
        try:
            with open(RESULTS_FILE) as fh:
                data = json.load(fh)
            return {
                "status":        "available",
                "total_matches": data.get("total_matches", 0),
                "unique_rules":  len(data.get("matched_rules", [])),
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
    return {"status": "no_data", "message": "Run the rule analysis pipeline first."}


# ── LM Studio endpoints ────────────────────────────────────────────────────────

@router.get("/lm-studio/status")
async def lm_studio_status() -> Dict:
    """Check whether LM Studio is running and return configuration."""
    reachable = lm_studio_reachable()
    return {
        "reachable":   reachable,
        "base_url":    LM_STUDIO_BASE_URL,
        "model":       LM_STUDIO_MODEL,
        "rule_data":   RESULTS_FILE.exists(),
        "anomaly_data": ANOMALY_FILE.exists(),
    }


@router.post("/lm-studio/insights")
async def lm_studio_insights() -> Dict:
    """
    Send rule-match results + anomaly scores to local LM Studio and return
    combined threat insights, natural language explanation, and mitigations.
    """
    rule_data    = _load_results()
    anomaly_data = []
    if ANOMALY_FILE.exists():
        try:
            anomaly_data = _load_anomalies()
        except Exception as exc:
            logger.warning(f"Could not load anomaly data: {exc}")

    result = analyse_with_lm_studio(rule_data, anomaly_data or None)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return result


@router.post("/lm-studio/anomaly-insights")
async def lm_studio_anomaly_insights() -> Dict:
    """Send only anomaly scores to LM Studio for natural-language explanation."""
    anomaly_data = _load_anomalies()
    result = analyse_anomalies_with_lm_studio(anomaly_data)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return result


@router.post("/lm-studio/rule-insights")
async def lm_studio_rule_insights() -> Dict:
    """Send only rule-match results to LM Studio for focused threat analysis."""
    rule_data = _load_results()
    result    = analyse_with_lm_studio(rule_data, anomaly_data=None)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return result