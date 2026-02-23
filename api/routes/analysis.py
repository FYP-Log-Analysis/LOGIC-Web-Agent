"""
Analysis Routes — LOGIC Web Agent
LLM-powered threat intelligence (Groq Cloud only) and on-demand
analysis pipeline (rule-based + ML anomaly detection).
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict, Optional
from api.services.llm_service import analyse_detection_results, analyse_specific_match
import json
import logging
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)
router = APIRouter()

RESULTS_FILE = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "rule_matches.json"
ANOMALY_FILE = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "anomaly_scores.json"
NORMALISED   = Path(__file__).resolve().parents[2] / "data" / "processed" / "normalized" / "normalized_logs.json"
RULES_FOLDER = Path(__file__).resolve().parents[2] / "analysis" / "detection" / "rules"


def _load_results() -> Dict:
    if not RESULTS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail="No detection results found. Run analysis first.",
        )
    with open(RESULTS_FILE, "r") as fh:
        return json.load(fh)


# ── Groq threat-insights endpoints ────────────────────────────────────────────

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
    return {"status": "no_data", "message": "Run analysis pipeline first."}


# ── On-demand analysis pipeline ────────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    mode:     str = "auto"          # "auto" | "manual"
    start_ts: Optional[str] = None  # ISO 8601, only used in manual mode
    end_ts:   Optional[str] = None  # ISO 8601, only used in manual mode


# In-memory run tracking (keyed by run_id)
_analysis_runs: dict = {}


def _run_analysis_task(
    run_id: str,
    start_ts: str | None,
    end_ts:   str | None,
) -> None:
    """Background task: run rule detection + ML analysis with optional time filter."""
    from analysis.rule_pipeline import run_rule_pipeline_from_file
    from ml.isolation_forest import run_isolation_forest
    import time

    _analysis_runs[run_id]["status"] = "running"
    steps = []

    try:
        # Step 1 — Rule detection
        t0 = time.time()
        _analysis_runs[run_id]["current_step"] = "rule_detection"
        rule_result = run_rule_pipeline_from_file(
            NORMALISED, RULES_FOLDER, start_ts=start_ts, end_ts=end_ts
        )
        steps.append({
            "step":          "rule_detection",
            "status":        "complete",
            "elapsed_s":     round(time.time() - t0, 1),
            "total_matches": rule_result.get("total_matches", 0),
            "unique_rules":  len(rule_result.get("matched_rules", [])),
        })

        # Step 2 — ML anomaly detection
        t1 = time.time()
        _analysis_runs[run_id]["current_step"] = "ml_detection"
        ml_result = run_isolation_forest(start_ts=start_ts, end_ts=end_ts)
        steps.append({
            "step":          "ml_detection",
            "status":        "complete",
            "elapsed_s":     round(time.time() - t1, 1),
            "total_entries": ml_result.get("total", 0),
            "anomaly_count": ml_result.get("anomaly_count", 0),
        })

        _analysis_runs[run_id].update({
            "status":  "complete",
            "steps":   steps,
            "current_step": None,
        })

    except Exception as exc:
        logger.error(f"Analysis task {run_id} failed: {exc}", exc_info=True)
        _analysis_runs[run_id].update({
            "status":    "failed",
            "error_msg": str(exc)[:500],
            "steps":     steps,
        })


@router.post("/run")
async def run_analysis(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks,
) -> Dict:
    """
    Start the rule-based + ML analysis pipeline.
    mode=auto:   analyse all stored logs
    mode=manual: analyse only logs within [start_ts, end_ts]
    Returns a run_id to poll via GET /api/analysis/run/{run_id}.
    """
    if not NORMALISED.exists():
        raise HTTPException(
            status_code=400,
            detail="No normalised log data found. Upload and ingest logs first.",
        )

    start_ts = request.start_ts if request.mode == "manual" else None
    end_ts   = request.end_ts   if request.mode == "manual" else None

    run_id = str(uuid.uuid4())
    _analysis_runs[run_id] = {
        "run_id":       run_id,
        "mode":         request.mode,
        "start_ts":     start_ts,
        "end_ts":       end_ts,
        "status":       "pending",
        "current_step": None,
        "steps":        [],
        "error_msg":    None,
    }

    background_tasks.add_task(_run_analysis_task, run_id, start_ts, end_ts)

    return {
        "status":  "accepted",
        "run_id":  run_id,
        "message": f"Analysis started. Poll GET /api/analysis/run/{run_id} for status.",
    }


@router.get("/run/{run_id}")
async def get_analysis_run(run_id: str) -> Dict:
    """Poll the status of a running or completed analysis."""
    record = _analysis_runs.get(run_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"No analysis run found with id '{run_id}'")
    return record
