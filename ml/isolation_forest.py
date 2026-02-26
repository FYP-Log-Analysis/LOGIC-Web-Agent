# Unsupervised anomaly detection using Isolation Forest.
# Two-pass streaming design: pass 1 extracts features into numpy, pass 2 writes scored output.
# Uses ijson throughout so even multi-GB log files never fully load into RAM.
import json
import logging
from pathlib import Path
from urllib.parse import urlsplit

import ijson
import numpy as np
from sklearn.ensemble import IsolationForest

from ml.feature_extraction import extract_features, FEATURE_NAMES
from analysis.sqlite_store import init_db, bulk_insert_anomalies

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
NORMALISED    = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
PARSED        = PROJECT_ROOT / "data" / "processed" / "json" / "parsed_logs.json"
RESULTS_DIR   = PROJECT_ROOT / "data" / "detection_results"


def _map_parsed_entry(entry: dict) -> dict:
    raw_path = entry.get("path") or "/"
    # Split path from query string gracefully (handles paths without '?')
    split    = urlsplit(raw_path)
    return {
        **entry,
        "client_ip":     entry.get("ip"),
        "http_method":   entry.get("method"),
        "request_path":  split.path or raw_path,
        "query_string":  split.query or "",
        "status_code":   entry.get("status", 0),
        "response_size": entry.get("size", 0),
    }


def _resolve_input() -> tuple[Path, bool]:
    if NORMALISED.exists():
        logger.info(f"Using normalised logs: {NORMALISED}")
        return NORMALISED, False
    if PARSED.exists():
        logger.info(
            f"Normalised logs not found — falling back to parsed logs: {PARSED}\n"
            "  (normalization step is not required for ML analysis)"
        )
        return PARSED, True
    return NORMALISED, False  # will trigger the existing 'not found' error path

CONTAMINATION = 0.05
RANDOM_STATE  = 42
_LOG_EVERY    = 100_000


def run_isolation_forest(
    start_ts:   str | None = None,
    end_ts:     str | None = None,
    project_id: str | None = None,
) -> dict:
    input_path, needs_mapping = _resolve_input()

    if not input_path.exists():
        logger.error(
            f"No input data found.\n"
            f"  Checked: {NORMALISED}\n"
            f"  Checked: {PARSED}\n"
            "  Run ingestion + parsing (or full normalization) first."
        )
        return {}

    # ── Pass 1: stream-extract features (with optional time-range filter) ─────
    logger.info("Pass 1 — extracting features …")
    feature_rows: list[list[float]] = []
    kept_indices: list[int]         = []
    with open(input_path, "rb") as fh:
        for i, raw_entry in enumerate(ijson.items(fh, "item")):
            ts = raw_entry.get("timestamp", "")
            if start_ts and ts and ts < start_ts:
                continue
            if end_ts and ts and ts > end_ts:
                continue
            entry = _map_parsed_entry(raw_entry) if needs_mapping else raw_entry
            row = extract_features(entry)
            feature_rows.append([row[f] for f in FEATURE_NAMES])
            kept_indices.append(i)
            if (len(feature_rows)) % _LOG_EVERY == 0:
                logger.info(f"  … {len(feature_rows):,} entries read")

    total = len(feature_rows)
    logger.info(f"Feature extraction complete: {total:,} entries × {len(FEATURE_NAMES)} features")

    X = np.array(feature_rows, dtype=float)
    del feature_rows  # free before fitting

    # ── Fit model ─────────────────────────────────────────────────────────────
    logger.info("Fitting Isolation Forest …")
    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)

    predictions = model.predict(X)       # 1 = normal / -1 = anomaly
    raw_scores  = model.score_samples(X)
    norm_scores = 1 - (raw_scores - raw_scores.min()) / (
        raw_scores.max() - raw_scores.min() + 1e-9
    )
    del X  # free numpy arrays before writing output

    anomaly_count = int((predictions == -1).sum())
    logger.info(f"Anomalies: {anomaly_count:,} / {total:,} ({100*anomaly_count/total:.1f}%)")

    # ── Pass 2: stream entries + scores → write output incrementally ──────────
    logger.info("Pass 2 — writing scored output …")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "anomaly_scores.json"

    kept_set = set(kept_indices)
    written  = 0
    global_i = 0
    first    = True
    _sqlite_batch: list[dict] = []
    _BATCH_SIZE = 5_000
    with open(input_path, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
        fout.write("[\n")
        for raw_entry in ijson.items(fin, "item"):
            if global_i in kept_set:
                entry = _map_parsed_entry(raw_entry) if needs_mapping else raw_entry
                scored_entry = {
                    **entry,
                    "is_anomaly":    bool(predictions[written] == -1),
                    "anomaly_score": float(round(norm_scores[written], 4)),
                    "raw_if_score":  float(round(raw_scores[written], 4)),
                }
                if not first:
                    fout.write(",\n")
                fout.write(json.dumps(scored_entry, ensure_ascii=False))
                first = False
                _sqlite_batch.append(scored_entry)
                if len(_sqlite_batch) >= _BATCH_SIZE:
                    try:
                        bulk_insert_anomalies(_sqlite_batch, project_id=project_id)
                    except Exception as exc:
                        logger.warning(f"SQLite batch insert skipped: {exc}")
                    _sqlite_batch.clear()
                written += 1
                if written % _LOG_EVERY == 0:
                    logger.info(f"  … {written:,} entries written")
            global_i += 1
        fout.write("\n]")
    # flush remaining batch
    if _sqlite_batch:
        try:
            bulk_insert_anomalies(_sqlite_batch, project_id=project_id)
        except Exception as exc:
            logger.warning(f"SQLite final batch insert skipped: {exc}")

    logger.info(f"Anomaly scores saved → {out_path}")
    return {
        "total":         total,
        "anomaly_count": anomaly_count,
        "output_file":   str(out_path),
    }


if __name__ == "__main__":
    result = run_isolation_forest()
    print(f"ML complete: {result.get('anomaly_count', 0)} anomalies in {result.get('total', 0)} entries")

