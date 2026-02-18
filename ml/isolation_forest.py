"""
Isolation Forest Anomaly Detection — LOGIC Web Agent
Runs unsupervised anomaly detection on normalised web log features.
Output → data/detection_results/anomaly_scores.json
"""

import json
import logging
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

try:
    from ml.feature_engineering.feature_extraction import extract_features, FEATURE_NAMES
except ImportError:
    from feature_engineering.feature_extraction import extract_features, FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
NORMALISED    = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
RESULTS_DIR   = PROJECT_ROOT / "data" / "detection_results"

# Tune here
CONTAMINATION = 0.05   # expected fraction of anomalies (~5 %)
RANDOM_STATE  = 42


def score_entries(log_entries: list[dict]) -> list[dict]:
    """
    Fit Isolation Forest on feature matrix and annotate each entry with
    'anomaly_score' (-1 = anomaly, 1 = normal) and 'anomaly_probability'.
    """
    if not log_entries:
        logger.warning("No log entries to score.")
        return []

    # Build feature matrix
    feature_rows = [extract_features(e) for e in log_entries]
    X = np.array([[row[f] for f in FEATURE_NAMES] for row in feature_rows], dtype=float)

    logger.info(f"Fitting Isolation Forest on {X.shape[0]:,} entries × {X.shape[1]} features …")
    model = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X)

    predictions   = model.predict(X)         # 1 normal / -1 anomaly
    raw_scores    = model.score_samples(X)    # more negative = more anomalous
    # Normalise to [0, 1] where 1 = most anomalous
    norm_scores   = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)

    scored = []
    for i, entry in enumerate(log_entries):
        scored.append({
            **entry,
            "is_anomaly":        bool(predictions[i] == -1),
            "anomaly_score":     float(round(norm_scores[i], 4)),
            "raw_if_score":      float(round(raw_scores[i], 4)),
        })

    anomaly_count = sum(1 for e in scored if e["is_anomaly"])
    logger.info(f"Anomalies detected: {anomaly_count:,} / {len(scored):,} ({100*anomaly_count/len(scored):.1f}%)")

    return scored


def run_isolation_forest() -> dict:
    if not NORMALISED.exists():
        logger.error(f"Normalised logs not found: {NORMALISED}  — run normalizer first.")
        return {}

    with open(NORMALISED, "r", encoding="utf-8") as fh:
        log_entries = json.load(fh)

    scored = score_entries(log_entries)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "anomaly_scores.json"
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(scored, fh, indent=2)
    logger.info(f"Anomaly scores saved → {out_path}")

    return {
        "total":          len(scored),
        "anomaly_count":  sum(1 for e in scored if e["is_anomaly"]),
        "output_file":    str(out_path),
    }


if __name__ == "__main__":
    result = run_isolation_forest()
    print(f"ML complete: {result.get('anomaly_count', 0)} anomalies in {result.get('total', 0)} entries")
