# Sole rule-based detection engine — runs normalised logs through the OWASP CRS service
# and writes matches to data/detection_results/rule_matches.json + the SQLite crs_matches table.

import json
import logging
from pathlib import Path

from analysis.sqlite_store import init_db, bulk_insert_crs_matches

try:
    from analysis.detection.crs_processor import run_crs_detection
    _CRS_AVAILABLE = True
except Exception as _e:
    _CRS_AVAILABLE = False
    logging.getLogger(__name__).warning(f"[CRS] crs_processor unavailable: {_e}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NORMALISED   = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
RESULTS_DIR  = PROJECT_ROOT / "data" / "detection_results"


def _crs_severity(score: float) -> str:
    if score >= 10: return "critical"
    if score >= 5:  return "high"
    if score >= 2:  return "medium"
    return "low"


def _crs_to_rule_match(cm: dict) -> dict:
    # Map the raw CRS result dict into the unified rule_matches.json format
    orig = cm.get("original_entry") or {}
    return {
        "rule_id":       f"CRS-{cm.get('rule_id', 'unknown')}",
        "rule_title":    f"[CRS] {cm.get('message', 'ModSecurity Rule')}",
        "severity":      _crs_severity(float(cm.get("anomaly_score") or 0)),
        "client_ip":     cm.get("client_ip") or orig.get("client_ip", "N/A"),
        "timestamp":     cm.get("timestamp") or orig.get("timestamp", "N/A"),
        "method":        cm.get("method") or orig.get("http_method"),
        "path":          cm.get("uri") or orig.get("request_path"),
        "status_code":   orig.get("status_code"),
        "user_agent":    orig.get("user_agent"),
        "entry":         orig,
        "anomaly_score": cm.get("anomaly_score", 0),
        "crs_tags":      cm.get("tags", "[]"),
    }


def _write_results(matches: list, crs_count: int, out_path: Path) -> dict:
    rule_ids = list({m["rule_id"] for m in matches})
    results_data = {
        "matches":       matches,
        "matched_rules": rule_ids,
        "total_matches": len(matches),
        "crs_matches":   crs_count,
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results_data, fh, indent=2)
    return results_data


def run_rule_pipeline_from_file(
    normalised_path,
    rules_folder=None,   # kept for backward compat — unused (CRS only)
    start_ts: str | None = None,
    end_ts:   str | None = None,
) -> dict:
    # CRS-only entry point — sends every normalised entry through ModSecurity
    # and writes matches to rule_matches.json
    normalised_path = Path(normalised_path)
    if not normalised_path.exists():
        logger.error(f"Normalised logs not found: {normalised_path} — run processor first.")
        return {"matches": [], "matched_rules": [], "total_matches": 0, "crs_matches": 0}

    out_path = RESULTS_DIR / "rule_matches.json"
    matches: list[dict] = []
    crs_count = 0

    if not _CRS_AVAILABLE:
        logger.warning("[CRS] crs_processor not available — writing empty results.")
        return _write_results(matches, crs_count, out_path)

    try:
        logger.info("[CRS] Running OWASP ModSecurity CRS detection …")
        crs_raw = run_crs_detection(
            normalized_path=normalised_path,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        if crs_raw:
            try:
                init_db()
                bulk_insert_crs_matches(crs_raw)
            except Exception as exc:
                logger.warning(f"[CRS] SQLite insert skipped: {exc}")
            matches = [_crs_to_rule_match(cm) for cm in crs_raw]
            crs_count = len(crs_raw)
            logger.info(f"[CRS] {crs_count} matches found.")
        else:
            logger.info("[CRS] 0 matches (CRS service may be unavailable).")
    except Exception as exc:
        logger.warning(f"[CRS] Detection step failed: {exc}")

    return _write_results(matches, crs_count, out_path)


def run_rule_pipeline(log_entries, rules_folder=None) -> dict:
    # In-memory variant — log_entries is accepted for API compatibility but CRS always reads from disk
    return run_rule_pipeline_from_file(NORMALISED)


def main():
    if not NORMALISED.exists():
        logger.error(f"Normalised logs not found: {NORMALISED} — run processor first.")
        return

    if not _CRS_AVAILABLE:
        logger.error("[CRS] crs_processor module not available — cannot run detection.")
        return

    logger.info("[CRS] Starting CRS-only rule pipeline …")
    result = run_rule_pipeline_from_file(NORMALISED)
    print(
        f"[CRS] Detection complete — "
        f"{result['crs_matches']} CRS matches "
        f"({result['total_matches']} total) written to "
        f"{RESULTS_DIR / 'rule_matches.json'}"
    )


if __name__ == "__main__":
    main()
