"""
Rule Pipeline — LOGIC Web Agent
Streams normalised logs via ijson, matches each entry against YAML detection
rules, and writes matches incrementally to
data/detection_results/rule_matches.json.
"""

import os
import json
import logging
from pathlib import Path

import ijson

from analysis.rule_load  import load_rules
from analysis.rule_match import check_if_entry_matches_rule
from analysis.sqlite_store import init_db, bulk_insert_detections

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
NORMALISED     = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
RULES_FOLDER   = PROJECT_ROOT / "analysis" / "detection" / "rules"
RESULTS_DIR    = PROJECT_ROOT / "data" / "detection_results"

_LOG_EVERY = 100_000


def run_rule_pipeline_from_file(normalised_path: Path | str, rules_folder: Path | str) -> dict:
    """
    Streaming entry point: never loads the full JSON into RAM.
    Reads normalised_logs.json via ijson and matches each entry against rules.
    This is the primary path called by run_pipeline.py and the CLI.
    """
    normalised_path = Path(normalised_path)
    if not normalised_path.exists():
        logger.error(f"Normalised logs not found: {normalised_path} — run processor first.")
        return {"matches": [], "matched_rules": [], "total_matches": 0}

    rules              = load_rules(rules_folder)
    matches: list[dict]        = []
    matched_rule_ids: set[str] = set()

    with open(normalised_path, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            for rule in rules:
                if check_if_entry_matches_rule(entry, rule):
                    rule_id = rule.get("id", "unknown")
                    matched_rule_ids.add(rule_id)
                    matches.append({
                        "rule_id":     rule_id,
                        "rule_title":  rule.get("title", "Unnamed Rule"),
                        "severity":    rule.get("level", "unknown"),
                        "client_ip":   entry.get("client_ip", "N/A"),
                        "timestamp":   entry.get("timestamp", "N/A"),
                        "method":      entry.get("http_method"),
                        "path":        entry.get("request_path"),
                        "status_code": entry.get("status_code"),
                        "user_agent":  entry.get("user_agent"),
                        "entry":       entry,
                    })
                    logger.info(
                        f"ALERT #{len(matches)}: [{rule.get('level','?').upper()}] "
                        f"{rule.get('title')} | {entry.get('client_ip')} "
                        f"{entry.get('http_method')} {entry.get('request_path')}"
                    )

    results_data = {
        "matches":       matches,
        "matched_rules": list(matched_rule_ids),
        "total_matches": len(matches),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "rule_matches.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)

    # ── Persist to SQLite ──────────────────────────────────────────────────
    try:
        init_db()
        bulk_insert_detections(matches)
    except Exception as exc:
        logger.warning(f"SQLite insert skipped: {exc}")

    logger.info(
        f"\n{'='*60}\n"
        f"Rule Detection Summary\n"
        f"Total Matches   : {len(matches)}\n"
        f"Unique Rules    : {len(matched_rule_ids)}\n"
        f"Results saved \u2192 : {out_path}\n"
        f"{'='*60}"
    )
    return results_data


def run_rule_pipeline(log_entries, rules_folder: Path | str) -> dict:
    """
    In-memory variant: accepts an already-loaded list of entries.
    Used by the API pipeline routes and unit tests.
    Writes results to disk and SQLite the same way as the streaming path.
    """
    rules   = load_rules(rules_folder)
    matches = []
    matched_rule_ids: set[str] = set()

    for entry in log_entries:
        for rule in rules:
            if check_if_entry_matches_rule(entry, rule):
                rule_id = rule.get("id", "unknown")
                matched_rule_ids.add(rule_id)
                matches.append({
                    "rule_id":     rule_id,
                    "rule_title":  rule.get("title", "Unnamed Rule"),
                    "severity":    rule.get("level", "unknown"),
                    "client_ip":   entry.get("client_ip", "N/A"),
                    "timestamp":   entry.get("timestamp", "N/A"),
                    "method":      entry.get("http_method"),
                    "path":        entry.get("request_path"),
                    "status_code": entry.get("status_code"),
                    "user_agent":  entry.get("user_agent"),
                    "entry":       entry,
                })
                logger.info(
                    f"ALERT #{len(matches)}: [{rule.get('level','?').upper()}] "
                    f"{rule.get('title')} | {entry.get('client_ip')} "
                    f"{entry.get('http_method')} {entry.get('request_path')}"
                )

    results_data = {
        "matches":       matches,
        "matched_rules": list(matched_rule_ids),
        "total_matches": len(matches),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "rule_matches.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)

    # ── Persist to SQLite ─────────────────────────────────────────────────────
    try:
        init_db()
        bulk_insert_detections(matches)
    except Exception as exc:
        logger.warning(f"SQLite insert skipped: {exc}")

    logger.info(
        f"\n{'='*60}\n"
        f"Rule Detection Summary\n"
        f"Total Matches   : {len(matches)}\n"
        f"Unique Rules    : {len(matched_rule_ids)}\n"
        f"Results saved → : {out_path}\n"
        f"{'='*60}"
    )
    return results_data


def main():
    """
    Streaming entry point: streams normalised logs with ijson so the full
    824 MB file is never loaded into RAM at once.
    """
    if not NORMALISED.exists():
        logger.error(f"Normalised logs not found: {NORMALISED}  — run normalizer first.")
        return

    rules = load_rules(RULES_FOLDER)
    logger.info(f"Loaded {len(rules)} detection rules")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "rule_matches.json"

    matches: list[dict]       = []
    matched_rule_ids: set[str] = set()
    processed = 0

    logger.info("Streaming log entries for rule matching …")
    with open(NORMALISED, "rb") as fh:
        for entry in ijson.items(fh, "item"):
            for rule in rules:
                if check_if_entry_matches_rule(entry, rule):
                    rule_id = rule.get("id", "unknown")
                    matched_rule_ids.add(rule_id)
                    matches.append({
                        "rule_id":     rule_id,
                        "rule_title":  rule.get("title", "Unnamed Rule"),
                        "severity":    rule.get("level", "unknown"),
                        "client_ip":   entry.get("client_ip", "N/A"),
                        "timestamp":   entry.get("timestamp", "N/A"),
                        "method":      entry.get("http_method"),
                        "path":        entry.get("request_path"),
                        "status_code": entry.get("status_code"),
                        "user_agent":  entry.get("user_agent"),
                        "entry":       entry,
                    })
            processed += 1
            if processed % _LOG_EVERY == 0:
                logger.info(f"  … {processed:,} entries checked | {len(matches):,} matches so far")

    results_data = {
        "matches":       matches,
        "matched_rules": list(matched_rule_ids),
        "total_matches": len(matches),
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)

    logger.info(
        f"\n{'='*60}\n"
        f"Rule Detection Summary\n"
        f"Total Entries   : {processed:,}\n"
        f"Total Matches   : {len(matches):,}\n"
        f"Unique Rules    : {len(matched_rule_ids)}\n"
        f"Results saved → : {out_path}\n"
        f"{'='*60}"
    )
    print(f"Rule detection complete: {len(matches)} matches in {processed:,} entries")


if __name__ == "__main__":
    main()
