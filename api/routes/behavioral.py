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

_RESULTS_PATH = Path(__file__).resolve().parents[2] / "data" / "detection_results" / "behavioral_results.json"


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


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.post("/behavioral")
def run_behavioral(req: BehavioralRequest, _user: UserInDB = Depends(get_current_user)):
    """Run all behavioral detections and persist results."""
    try:
        from analysis.behavioral import run_behavioral_analysis
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
def get_behavioral_results(_user: UserInDB = Depends(get_current_user)):
    """Return the latest behavioral_results.json."""
    if not _RESULTS_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail="No behavioral results found. Run POST /api/analysis/behavioral first.",
        )
    try:
        with open(_RESULTS_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read results: {exc}")


@router.get("/behavioral/alerts")
def get_behavioral_alerts(
    alert_type: Optional[str] = Query(None, description="Filter by alert type"),
    client_ip:  Optional[str] = Query(None, description="Filter by client IP"),
    limit:      int           = Query(500,  ge=1, le=5000),
    offset:     int           = Query(0,    ge=0),
    _user:      UserInDB      = Depends(get_current_user),
):
    """Query the behavioral_alerts SQLite table."""
    try:
        from analysis.sqlite_store import get_behavioral_alerts as _get
        return {"alerts": _get(alert_type=alert_type, client_ip=client_ip, limit=limit, offset=offset)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
