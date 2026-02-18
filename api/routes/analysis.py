"""
Analysis Routes — LOGIC Web Agent
LLM-powered threat intelligence endpoints.
"""

from fastapi import APIRouter, HTTPException
from typing import Dict
from api.services.llm_service import analyse_detection_results, analyse_specific_match
import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()

RESULTS_FILE = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "rule_matches.json"


def _load_results() -> Dict:
    if not RESULTS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No detection results found. Run the rule analysis pipeline first.",
        )
    with open(RESULTS_FILE, "r") as fh:
        return json.load(fh)


@router.post("/threat-insights")
async def get_threat_insights() -> Dict:
    """Generate AI-powered threat analysis from rule detection results."""
    detection_data = _load_results()
    result = analyse_detection_results(detection_data)
    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("error_message"))
    return {"status": "success", **result}


@router.post("/threat-insights/{rule_id}")
async def analyse_rule_match(rule_id: str) -> Dict:
    """Analyse a single detected rule match in detail."""
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
