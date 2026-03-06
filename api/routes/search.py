from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, Query
from core.storage.sqlite_store import (
    get_stats,
    get_ip_summary,
    query_detections,
)
from api.deps import UserInDB, get_current_user

router = APIRouter(prefix="/search", tags=["Search & Grafana"])


@router.get("/detections")
def get_detections(
    severity:  str | None = Query(None, description="Filter by severity: critical/high/medium/low"),
    rule_id:   str | None = Query(None, description="Filter by rule ID"),
    client_ip: str | None = Query(None, description="Filter by source IP"),
    limit:     int        = Query(100, le=2000),
    offset:    int        = Query(0),
    _user:     UserInDB   = Depends(get_current_user),
) -> dict[str, Any]:
    rows = query_detections(
        severity=severity, rule_id=rule_id,
        client_ip=client_ip, limit=limit, offset=offset,
    )
    return {"count": len(rows), "results": rows}



@router.get("/stats")
def get_summary_stats(_user: UserInDB = Depends(get_current_user)) -> dict[str, Any]:
    return get_stats()


@router.get("/ip-summary/{client_ip}")
def get_ip_summary_endpoint(
    client_ip: str,
    _user: UserInDB = Depends(get_current_user),
) -> dict[str, Any]:
    return get_ip_summary(client_ip)


# Grafana plugin: "SimpleJSON" (grafana-simple-json-datasource)
# Expose at /api/search/grafana/*

grafana = APIRouter(prefix="/search/grafana", tags=["Grafana SimpleJSON"])


@grafana.get("/")
def grafana_health() -> str:
    return "OK"


@grafana.post("/search")
def grafana_search() -> list[str]:
    return [
        "detections_total",
        "critical_detections",
        "high_detections",
        "detections_by_severity",
        "top_offending_ips",
    ]


@grafana.post("/query")
def grafana_query(body: dict[str, Any]) -> list[dict[str, Any]]:
    stats   = get_stats()
    now_ms  = int(time.time() * 1000)
    results = []

    for target_obj in body.get("targets", []):
        target = target_obj.get("target", "")

        if target == "detections_total":
            results.append({
                "target": "Total Detections",
                "datapoints": [[stats["total_detections"], now_ms]],
            })


        elif target == "critical_detections":
            count = stats["detections_by_severity"].get("critical", 0)
            results.append({
                "target": "Critical Detections",
                "datapoints": [[count, now_ms]],
            })

        elif target == "high_detections":
            count = stats["detections_by_severity"].get("high", 0)
            results.append({
                "target": "High Detections",
                "datapoints": [[count, now_ms]],
            })

        elif target == "detections_by_severity":
            results.append({
                "columns": [
                    {"text": "Severity", "type": "string"},
                    {"text": "Count",    "type": "number"},
                ],
                "rows": [
                    [sev, cnt]
                    for sev, cnt in stats["detections_by_severity"].items()
                ],
                "type": "table",
            })

        elif target == "top_offending_ips":
            results.append({
                "columns": [
                    {"text": "IP Address", "type": "string"},
                    {"text": "Hit Count",  "type": "number"},
                ],
                "rows": [
                    [row["client_ip"], row["hit_count"]]
                    for row in stats["top_offending_ips"]
                ],
                "type": "table",
            })

    return results


@grafana.post("/annotations")
def grafana_annotations(body: dict[str, Any]) -> list:
    return []
