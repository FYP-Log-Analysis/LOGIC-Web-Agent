# Data Directory — LOGIC Web Agent

| Sub-folder | Contents |
|---|---|
| `raw_logs/` | Raw `.log` / `.gz` files to analyse |
| `intermediate/` | `raw_entries.json` — output of ingestion step |
| `processed/json/` | `parsed_logs.json` — structured parsed records |
| `processed/normalized/` | `normalized_logs.json` — enriched, standardised records |
| `features/` | Feature matrices (optional persistence) |
| `detection_results/` | `rule_matches.json`, `anomaly_scores.json` |

Drop your web server log files into `raw_logs/` and run the pipeline.
