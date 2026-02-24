from fastapi import APIRouter, HTTPException
from api.services.pipeline_service import (
    run_pipeline,
    get_pipeline_steps,
    run_step,
    run_steps_in_sequence,
)
from analysis.sqlite_store import get_pipeline_runs, get_pipeline_run

router = APIRouter()


@router.get("/steps")
def get_steps():
    return {"steps": get_pipeline_steps()}


@router.post("/run/{step_id}")
def run_single_step(step_id: str):
    return run_step(step_id)


@router.post("/run-sequence")
def run_sequence(step_ids: list[str]):
    return run_steps_in_sequence(step_ids)


@router.post("/run")
def run_full_pipeline():
    return run_pipeline()


@router.get("/runs")
def list_runs(limit: int = 50):
    return {"runs": get_pipeline_runs(limit=limit)}


@router.get("/runs/{run_id}")
def get_run(run_id: str):
    record = get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return record
