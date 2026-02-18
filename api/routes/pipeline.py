from fastapi import APIRouter
from api.services.pipeline_service import (
    run_pipeline,
    get_pipeline_steps,
    run_step,
    run_steps_in_sequence,
)

router = APIRouter()


@router.get("/steps")
def get_steps():
    """List all available pipeline steps."""
    return {"steps": get_pipeline_steps()}


@router.post("/run/{step_id}")
def run_single_step(step_id: str):
    """Run a specific pipeline step by ID."""
    return run_step(step_id)


@router.post("/run-sequence")
def run_sequence(step_ids: list[str]):
    """Run a list of pipeline steps in order."""
    return run_steps_in_sequence(step_ids)


@router.post("/run")
def run_full_pipeline():
    """Run the complete ingestion → detection pipeline."""
    return run_pipeline()
