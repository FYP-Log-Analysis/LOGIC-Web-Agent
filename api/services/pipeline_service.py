import subprocess
import sys
import os
from typing import Dict, List
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

PIPELINE_STEPS = {
    "ingestion": {
        "name":        "Log Ingestion",
        "description": "Read raw .log / .gz files → data/intermediate/raw_entries.json",
        "script":      "ingestion/src/ingest_logs.py",
        "order":       1,
    },
    "parsing": {
        "name":        "Log Parsing",
        "description": "Parse Combined Log Format → data/processed/json/parsed_logs.json",
        "script":      "parser/src/parse_logs.py",
        "order":       2,
    },
    "normalization": {
        "name":        "Normalization",
        "description": "Standardise fields → data/processed/normalized/normalized_logs.json",
        "script":      "normalizer/src/normalize.py",
        "order":       3,
    },
    "rule_analysis": {
        "name":        "Rule-Based Detection",
        "description": "Run YAML detection rules → data/detection_results/rule_matches.json",
        "script":      "analysis/rule_pipeline.py",
        "order":       4,
    },
    "ml_analysis": {
        "name":        "ML Anomaly Detection",
        "description": "Isolation Forest scoring → data/detection_results/anomaly_scores.json",
        "script":      "ml/isolation_forest.py",
        "order":       5,
    },
}


def get_pipeline_steps() -> Dict:
    return PIPELINE_STEPS


def run_step(step_id: str) -> Dict:
    if step_id not in PIPELINE_STEPS:
        return {"status": "error", "message": f"Unknown step: {step_id}"}

    step_config = PIPELINE_STEPS[step_id]
    full_script = PROJECT_ROOT / step_config["script"]

    if not full_script.exists():
        return {
            "status": "failed",
            "step_id": step_id,
            "step_name": step_config["name"],
            "error_message": f"Script not found: {full_script}",
        }

    try:
        result = subprocess.run(
            [sys.executable, str(full_script)],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            timeout=3600,
        )
        return {
            "status":    "success" if result.returncode == 0 else "failed",
            "step_id":   step_id,
            "step_name": step_config["name"],
            "return_code": result.returncode,
            "output":    result.stdout[:1000] if result.stdout else "",
            "error":     result.stderr[:500]  if result.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"status": "timeout",  "step_id": step_id, "step_name": step_config["name"]}
    except Exception as exc:
        return {"status": "error",    "step_id": step_id, "step_name": step_config["name"], "error_message": str(exc)}


def run_steps_in_sequence(step_ids: List[str]) -> Dict:
    results, failed_step = [], None
    for step_id in step_ids:
        if step_id not in PIPELINE_STEPS:
            return {"status": "error", "message": f"Unknown step: {step_id}"}

    for step_id in step_ids:
        result = run_step(step_id)
        results.append(result)
        if result["status"] in {"failed", "timeout", "error"}:
            failed_step = step_id
            break

    return {
        "status":          "success" if not failed_step else "failed",
        "total_steps":     len(step_ids),
        "completed_steps": len([r for r in results if r["status"] == "success"]),
        "failed_step":     failed_step,
        "results":         results,
    }


def run_pipeline() -> Dict:
    all_steps = sorted(PIPELINE_STEPS.keys(), key=lambda x: PIPELINE_STEPS[x]["order"])
    return run_steps_in_sequence(all_steps)
