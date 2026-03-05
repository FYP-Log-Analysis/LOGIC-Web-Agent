from fastapi import APIRouter, Depends, HTTPException
from api.deps import UserInDB, get_current_user
from api.services.pipeline_service import (
    run_pipeline,
    get_pipeline_steps,
    run_step,
    run_steps_in_sequence,
)
from core.storage.sqlite_store import get_pipeline_runs, get_pipeline_run

router = APIRouter()


@router.get("/steps")
def get_steps(_user: UserInDB = Depends(get_current_user)):
    return {"steps": get_pipeline_steps()}


@router.post("/run/{step_id}")
def run_single_step(step_id: str, _user: UserInDB = Depends(get_current_user)):
    return run_step(step_id)


@router.post("/run-sequence")
def run_sequence(step_ids: list[str], _user: UserInDB = Depends(get_current_user)):
    return run_steps_in_sequence(step_ids)


@router.post("/run")
def run_full_pipeline(_user: UserInDB = Depends(get_current_user)):
    return run_pipeline()


@router.get("/runs")
def list_runs(limit: int = 50, _user: UserInDB = Depends(get_current_user)):
    return {"runs": get_pipeline_runs(limit=limit)}


@router.get("/runs/{run_id}")
def get_run(run_id: str, _user: UserInDB = Depends(get_current_user)):
    record = get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return record
