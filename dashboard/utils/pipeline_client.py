"""Pipeline API calls — steps, run, run individual step."""
from typing import Dict
from utils.api_client import _get, _post


def get_pipeline_steps() -> Dict:
    return _get("/api/pipeline/steps")


def run_pipeline() -> Dict:
    return _post("/api/pipeline/run")


def run_pipeline_step(step_id: str) -> Dict:
    return _post(f"/api/pipeline/run/{step_id}")
