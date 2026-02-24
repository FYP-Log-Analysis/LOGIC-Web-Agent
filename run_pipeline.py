#!/usr/bin/env python3
# Runs all pipeline stages in order: ingest → process → rule detect → ML anomaly detect.
# Execute from the project root: python run_pipeline.py

import sys
import time
import logging
from pathlib import Path

# Make sure the project root is importable regardless of where the script is called from
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline")

# Colour output only on real terminals — Windows cmd doesn't play well with ANSI codes
_USE_COLOUR = sys.platform != "win32" and sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

BOLD    = lambda t: _c("1",      t)
GREEN   = lambda t: _c("32",     t)
YELLOW  = lambda t: _c("33",     t)
CYAN    = lambda t: _c("36",     t)
RED     = lambda t: _c("31",     t)
MAGENTA = lambda t: _c("35",     t)


def _banner(title: str) -> None:
    width = 64
    print()
    print(CYAN("─" * width))
    print(CYAN(f"  {title}"))
    print(CYAN("─" * width))


def _step(n: int, total: int, label: str) -> None:
    print()
    print(BOLD(f"[{n}/{total}]  {label}"))


def _ok(label: str, elapsed: float, detail: str = "") -> None:
    suffix = f"  ({detail})" if detail else ""
    print(GREEN(f"  ✓  {label} completed in {elapsed:.1f}s{suffix}"))


def _fail(label: str, err: Exception) -> None:
    print(RED(f"  ✗  {label} FAILED: {err}"))


def _summary_row(label: str, value: str) -> None:
    print(f"  {BOLD(f'{label:<22}')} {value}")


# Each stage function imports its module lazily so failures are isolated

def stage_ingest() -> dict:
    from ingestion.ingest_logs import ingest_all
    entries = ingest_all()
    return {"entries": len(entries)}


def stage_process() -> dict:
    # Single streaming pass: parse raw lines and normalise in one go
    from processor.process_logs import process_all
    records = process_all()
    return {"records": records}


def stage_rules() -> dict:
    from analysis.rule_pipeline import run_rule_pipeline_from_file
    normalised_path = PROJECT_ROOT / "data" / "processed" / "normalized" / "normalized_logs.json"
    rules_folder    = PROJECT_ROOT / "analysis" / "detection" / "rules"
    result = run_rule_pipeline_from_file(normalised_path, rules_folder)
    return {
        "total_matches": result.get("total_matches", 0),
        "unique_rules":  len(result.get("matched_rules", [])),
    }


def stage_ml() -> dict:
    from ml.isolation_forest import run_isolation_forest
    result = run_isolation_forest()
    return {
        "total":         result.get("total", 0),
        "anomaly_count": result.get("anomaly_count", 0),
    }


STAGES = [
    ("Ingestion",             stage_ingest),
    ("Processing",            stage_process),   # parse + normalise in one pass
    ("Rule Detection",        stage_rules),
    ("ML — Isolation Forest", stage_ml),
]


def main() -> None:
    _banner("LOGIC Web Agent  ·  Full Pipeline")
    pipeline_start = time.time()

    # Set up the database schema before anything else runs
    try:
        from analysis.sqlite_store import init_db
        init_db()
        logger.info("SQLite database ready")
    except Exception as exc:
        logger.warning(f"SQLite init skipped: {exc}")

    results   = {}
    failed_at = None

    for i, (label, fn) in enumerate(STAGES, start=1):
        _step(i, len(STAGES), label)
        t0 = time.time()
        try:
            info = fn()
            elapsed = time.time() - t0
            results[label] = {"elapsed": elapsed, **info}

            # Turn whatever the stage returned into a readable one-liner
            detail = "  |  ".join(f"{k}: {v:,}" if isinstance(v, int) else f"{k}: {v}"
                                  for k, v in info.items())
            _ok(label, elapsed, detail)

        except Exception as exc:
            elapsed = time.time() - t0
            _fail(label, exc)
            logger.exception(f"Stage '{label}' raised an exception")
            failed_at = label
            results[label] = {"elapsed": elapsed, "error": str(exc)}
            break   # halt on first failure

    total_elapsed = time.time() - pipeline_start
    print()
    print(CYAN("═" * 64))
    print(BOLD("  Pipeline Summary"))
    print(CYAN("═" * 64))

    for label, info in results.items():
        elapsed = info.get("elapsed", 0)
        if "error" in info:
            status = RED(f"FAILED  ({info['error'][:55]})")
        else:
            extra = {k: v for k, v in info.items() if k != "elapsed"}
            status_parts = [f"{k}={v:,}" if isinstance(v, int) else f"{k}={v}"
                            for k, v in extra.items()]
            status = GREEN("OK") + (f"  [{', '.join(status_parts)}]" if status_parts else "")
        print(f"  {label:<28}  {elapsed:>6.1f}s   {status}")

    print(CYAN("─" * 64))
    print(f"  {'Total time':<28}  {total_elapsed:>6.1f}s")
    print(CYAN("═" * 64))

    if failed_at:
        print(RED(f"\n  Pipeline stopped at: {failed_at}"))
        sys.exit(1)
    else:
        print(GREEN("\n  All stages completed successfully."))

    # Show where each output file ended up and how big it is
    print()
    print(BOLD("  Output files:"))
    outputs = [
        ("Raw entries",     "data/intermediate/raw_entries.json"),
        ("Normalised logs", "data/processed/normalized/normalized_logs.json"),
        ("Rule matches",    "data/detection_results/rule_matches.json"),
        ("Anomaly scores",  "data/detection_results/anomaly_scores.json"),
    ]
    for name, rel_path in outputs:
        full = PROJECT_ROOT / rel_path
        size = f"{full.stat().st_size / 1_048_576:.1f} MB" if full.exists() else YELLOW("not found")
        print(f"  {name:<22}  {rel_path}  ({size})")
    print()


if __name__ == "__main__":
    main()
