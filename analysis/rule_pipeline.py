"""
Rule Pipeline — LOGIC Web Agent
Loads normalised logs + detection rules and saves matches to
data/detection_results/rule_matches.json.
"""

import os
import json
import logging
from pathlib import Path

try:
    from analysis.rule_load  import load_rules
    from analysis.rule_match import check_if_entry_matches_rule
except ImportError:
    from rule_load  import load_rules
    from rule_match import check_if_entry_matches_rule

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parent.parent
NORMALISED     = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
RULES_FOLDER   = PROJECT_ROOT / "analysis" / "detection" / "rules"
RESULTS_DIR    = PROJECT_ROOT / "data" / "detection_results"


def run_rule_pipeline(log_entries: list[dict], rules_folder: Path | str) -> dict:
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
        "matches":        matches,
        "matched_rules":  list(matched_rule_ids),
        "total_matches":  len(matches),
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "rule_matches.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)

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
    if not NORMALISED.exists():
        logger.error(f"Normalised logs not found: {NORMALISED}  — run normalizer first.")
        return

    with open(NORMALISED, "r", encoding="utf-8") as fh:
        log_entries = json.load(fh)

    run_rule_pipeline(log_entries, RULES_FOLDER)


if __name__ == "__main__":
    main()
