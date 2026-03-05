# LOGIC Web Agent

**Log Analysis for Web Server Logs — Check, Analyse, and Interpret**

LOGIC Web Agent is a forensics and threat-detection pipeline for web server access/error logs (Apache & Nginx). It mirrors the architecture of the LOGIC Windows Event Log project but targets HTTP-layer data.

## Architecture

```
Raw Logs (.log / .gz)
        │
        ▼
 [1] Ingestion        ingestion/src/ingest_logs.py
        │               Reads raw log files, decompresses .gz
        ▼
 [2] Parsing          parser/src/parse_logs.py
        │               Parses Apache/Nginx Combined Log Format → JSON
        ▼
 [3] Normalization    normalizer/src/normalize.py
        │               Standardises fields (ip, timestamp, method, path, status…)
        ▼
 [4] Rule Analysis    analysis/rule_pipeline.py
        │               YAML-based detection rules (SQLi, LFI, XSS, brute-force…)
        ▼
 [5] ML Detection     ml/isolation_forest.py
        │               Isolation Forest anomaly scoring on normalised features
        ▼
 [6] API              api/main.py  (FastAPI, port 4000)
        │               REST endpoints: pipeline control, upload, LLM insights
        ▼
 [7] Dashboard        frontend/  (Next.js, port 3000)
                        Overview, Anomaly Analysis, Rule Detection, Log Stats
```

## Quick Start

### Docker (recommended)
```bash
cp .env.example .env
# add GROQ_API_KEY to .env
docker-compose up --build
```
- Dashboard → http://localhost:3000
- API docs  → http://localhost:4000/docs

### Local development
```bash
pip install -r requirements.txt
# Run pipeline stages manually
python ingestion/src/ingest_logs.py
python parser/src/parse_logs.py
python normalizer/src/normalize.py
python analysis/rule_pipeline.py
python ml/isolation_forest.py
# Start API
uvicorn api.main:app --port 4000 --reload
# Start Dashboard (separate terminal)
cd frontend && npm install && npm run dev
```

## Data Flow

| Stage | Input | Output |
|-------|-------|--------|
| Ingestion | `data/raw_logs/*.log` / `*.gz` | `data/intermediate/raw_entries.json` |
| Parsing | raw_entries.json | `data/processed/json/*.json` |
| Normalization | processed json | `data/processed/normalized/*.json` |
| Rule Detection | normalized json | `data/detection_results/rule_matches.json` |
| ML Detection | normalized json | `data/detection_results/anomaly_scores.json` |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GROQ_API_KEY` | Groq Cloud API key for LLM threat insights |
| `API_BASE_URL` | Dashboard → API URL (default: `http://api:4000`) |

## Detection Rules

Custom YAML detection rules live in `analysis/detection/rules/`. Each rule file supports:
- `title`, `description`, `severity` (`critical` / `high` / `medium` / `low`)
- `detection.keywords` — substring matches against request fields
- `detection.patterns` — regex patterns
- `detection.conditions` — field-level matchers (status, method, threshold)

## Log Formats Supported

- Apache Combined Log Format
- Nginx default combined log format
- W3C Extended / IIS (via normalizer plugins)
