"""
Data Service — LOGIC Web Agent Dashboard
Loads result JSON files directly from the data/ directory for display.
"""

import json
import os
from pathlib import Path
from typing import Dict, List

import ijson  # streaming JSON parser — never loads multi-GB files into RAM

DATA_ROOT = Path(os.getenv("DATA_ROOT", "/app/data"))

# Cap how many rows are streamed into dashboard memory.
# Large JSON files (100k+ rows) will OOM the container if fully loaded.
_ANOMALY_LIMIT = int(os.getenv("ANOMALY_DISPLAY_LIMIT", "5000"))
_LOG_DISPLAY_LIMIT = int(os.getenv("LOG_DISPLAY_LIMIT", "5000"))


def _load_json(rel_path: str) -> dict | list | None:
    """Load a small JSON file (rule_matches etc.) fully into memory.
    Do NOT use this for large array files — use _stream_json_array() instead.
    """
    target = DATA_ROOT / rel_path
    if not target.exists():
        return None
    try:
        with open(target, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _stream_json_array(rel_path: str, limit: int) -> List[Dict]:
    """Stream the first `limit` items from a top-level JSON array without
    reading the whole file into memory.  Returns [] if the file is missing."""
    target = DATA_ROOT / rel_path
    if not target.exists():
        return []
    results: List[Dict] = []
    try:
        with open(target, "rb") as fh:
            for item in ijson.items(fh, "item"):
                results.append(item)
                if len(results) >= limit:
                    break
    except Exception:
        pass
    return results


def get_rule_matches() -> Dict:
    data = _load_json("detection_results/rule_matches.json")
    return data or {"matches": [], "matched_rules": [], "total_matches": 0}


def get_anomaly_scores() -> List[Dict]:
    # Stream only the first _ANOMALY_LIMIT rows — never load the full 800 MB+ file
    return _stream_json_array("detection_results/anomaly_scores.json", _ANOMALY_LIMIT)


def get_parsed_logs() -> List[Dict]:
    return _stream_json_array("processed/json/parsed_logs.json", _LOG_DISPLAY_LIMIT)


def get_normalized_logs() -> List[Dict]:
    return _stream_json_array("processed/normalized/normalized_logs.json", _LOG_DISPLAY_LIMIT)


def get_data_sizes() -> List[Dict]:
    """Return name, path, and human-readable size for every tracked data file."""
    tracked = [
        ("Raw Log (access.log)",          "raw_logs/access.log"),
        ("Parsed Logs (JSON)",             "processed/json/parsed_logs.json"),
        ("Normalised Logs (JSON)",          "processed/normalized/normalized_logs.json"),
        ("Rule Matches",                   "detection_results/rule_matches.json"),
        ("Anomaly Scores",                 "detection_results/anomaly_scores.json"),
        ("Raw Entries (ingestion)",        "intermediate/raw_entries.json"),
    ]
    results = []
    for label, rel in tracked:
        path = DATA_ROOT / rel
        if path.exists():
            bytes_ = path.stat().st_size
            if bytes_ >= 1_073_741_824:
                human = f"{bytes_ / 1_073_741_824:.2f} GB"
            elif bytes_ >= 1_048_576:
                human = f"{bytes_ / 1_048_576:.1f} MB"
            elif bytes_ >= 1_024:
                human = f"{bytes_ / 1_024:.1f} KB"
            else:
                human = f"{bytes_} B"
            results.append({"File": label, "Path": str(path.relative_to(DATA_ROOT)), "Size": human, "bytes": bytes_})
        else:
            results.append({"File": label, "Path": rel, "Size": "—", "bytes": 0})
    return results
