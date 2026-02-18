"""
Data Service — LOGIC Web Agent Dashboard
Loads result JSON files directly from the data/ directory for display.
"""

import json
import os
from pathlib import Path
from typing import Dict, List

DATA_ROOT = Path(os.getenv("DATA_ROOT", "/app/data"))


def _load_json(rel_path: str) -> dict | list | None:
    target = DATA_ROOT / rel_path
    if not target.exists():
        return None
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def get_rule_matches() -> Dict:
    data = _load_json("detection_results/rule_matches.json")
    return data or {"matches": [], "matched_rules": [], "total_matches": 0}


def get_anomaly_scores() -> List[Dict]:
    data = _load_json("detection_results/anomaly_scores.json")
    return data if isinstance(data, list) else []


def get_parsed_logs() -> List[Dict]:
    data = _load_json("processed/json/parsed_logs.json")
    return data if isinstance(data, list) else []


def get_normalized_logs() -> List[Dict]:
    data = _load_json("processed/normalized/normalized_logs.json")
    return data if isinstance(data, list) else []
