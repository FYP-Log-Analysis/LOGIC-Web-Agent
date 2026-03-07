"""
API routes for behavioral traffic analysis.

POST /api/analysis/behavioral          — run all 4 behavioral detections
GET  /api/analysis/behavioral/results  — return the latest behavioral_results.json
GET  /api/analysis/behavioral/alerts   — query SQLite behavioral_alerts table
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from api.deps import UserInDB, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

_PROJECT_ROOT  = Path(__file__).resolve().parents[2]
_RESULTS_PATH  = _PROJECT_ROOT / "data" / "detection_results" / "behavioral_results.json"


def _results_path(project_id: str | None) -> Path:
    if project_id:
        return _PROJECT_ROOT / "data" / "projects" / project_id / "detection_results" / "behavioral_results.json"
    return _RESULTS_PATH


# ── Request schemas ────────────────────────────────────────────────────────────

class BehavioralRequest(BaseModel):
    rate_window_minutes:    int   = 1
    rate_threshold:         int   = 60
    enum_window_hours:      int   = 1
    enum_threshold:         int   = 50
    status_window_minutes:  int   = 5
    status_error_ratio:     float = 0.50
    visitor_zscore:         float = 2.0
    start_ts:               Optional[str] = None
    end_ts:                 Optional[str] = None
    project_id:             Optional[str] = None


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/behavioral")
def run_behavioral(req: BehavioralRequest, _user: UserInDB = Depends(get_current_user)):
    """Run all behavioral detections and persist results."""
    try:
        from core.behavioral.behavioral import run_behavioral_analysis
        result = run_behavioral_analysis(
            rate_window_minutes   = req.rate_window_minutes,
            rate_threshold        = req.rate_threshold,
            enum_window_hours     = req.enum_window_hours,
            enum_threshold        = req.enum_threshold,
            status_window_minutes = req.status_window_minutes,
            status_error_ratio    = req.status_error_ratio,
            visitor_zscore        = req.visitor_zscore,
            start_ts              = req.start_ts,
            end_ts                = req.end_ts,
            project_id            = req.project_id,
        )
        return {
            "status":  "complete",
            "summary": result.get("summary", {}),
            "generated_at": result.get("generated_at"),
        }
    except Exception as exc:
        logger.exception("Behavioral analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/behavioral/results")
def get_behavioral_results(
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    _user: UserInDB = Depends(get_current_user),
):
    """Return the latest behavioral_results.json (project-scoped if project_id given)."""
    path = _results_path(project_id)
    if not path.exists():
        # Fall back to global results if no project-specific file exists yet
        if project_id and _RESULTS_PATH.exists():
            path = _RESULTS_PATH
        else:
            raise HTTPException(
                status_code=404,
                detail="No behavioral results found. Run POST /api/analysis/behavioral first.",
            )
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read results: {exc}")


@router.get("/behavioral/alerts")
def get_behavioral_alerts_route(
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    client_ip:  Optional[str] = Query(None, description="Filter by client IP"),
    project_id: Optional[str] = Query(None, description="Scope to a specific project"),
    start_ts:   Optional[str] = Query(None, description="Earliest timestamp (ISO 8601)"),
    end_ts:     Optional[str] = Query(None, description="Latest timestamp (ISO 8601)"),
    limit:      int           = Query(500,  ge=1, le=5000),
    offset:     int           = Query(0,    ge=0),
    _user:      UserInDB      = Depends(get_current_user),
):
    """Query the behavioral_alerts SQLite table."""
    try:
        from core.storage.sqlite_store import get_behavioral_alerts as _get
        return {"alerts": _get(
            alert_type=alert_type, client_ip=client_ip,
            project_id=project_id, start_ts=start_ts, end_ts=end_ts,
            limit=limit, offset=offset,
        )}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
