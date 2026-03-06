# LOGIC Web Agent

**Log Analysis for Web Server Logs — Check, Analyse, and Interpret**

LOGIC Web Agent is a full-stack forensics and threat-detection platform for web server access and error logs (Apache & Nginx). It ingests raw log files, runs them through a multi-stage detection pipeline powered by the OWASP ModSecurity Core Rule Set (CRS) and heuristic behavioral analysis, and surfaces findings through an interactive Next.js dashboard with an LLM-powered AI insights chat.

## Features

- **Multi-stage pipeline** — ingest → parse → normalize → detect → store, orchestrated via the API or CLI
- **OWASP CRS detection** — replays normalized requests against a live ModSecurity CRS container (DetectionOnly mode) and captures rule match details from its JSON audit log
- **Behavioral analysis** — SQLite-backed heuristics detect request-rate spikes, URL enumeration, status-code anomalies, and visitor-rate outliers without loading full tables into memory
- **AI insights** — Groq Cloud LLM (or a local LM Studio model) answers natural-language questions about detection results via a persistent chat interface
- **Project isolation** — each upload is scoped to its own project with separate data directories and detection results
- **Role-based access** — JWT authentication with `admin` and `analyst` roles; admin panel for user management
- **Grafana dashboards** — pre-provisioned Grafana panels powered by the Infinity data source querying the API
- **Fully containerised** — Docker Compose spins up the API, Next.js frontend, ModSecurity CRS service, and Grafana with a single command

## Architecture

```
Raw Logs (.log / .gz)
        │
        ▼
 [1] Ingestion         core/ingestion/ingest_logs.py
        │                Reads raw log files, decompresses .gz archives
        ▼
 [2] Parsing           core/processor/process_logs.py
        │                Parses Apache/Nginx Combined Log Format → JSON
        ▼
 [3] Normalization     core/processor/apache_norm.py
        │                Standardises fields: ip, timestamp, method, path, status…
        ▼
 [4] CRS Detection     core/detection/crs_processor.py
        │                Replays requests against OWASP ModSecurity CRS (HTTP)
        │                Parses JSON audit log → rule matches + anomaly scores
        ▼
 [5] Behavioral        core/behavioral/behavioral.py
        │                Rate spikes · URL enumeration · status anomalies · visitor outliers
        ▼
 [6] Storage           core/storage/sqlite_store.py
        │                SQLite — logs, crs_matches, behavioral results, users, projects
        ▼
 [7] API               api/main.py  (FastAPI, port 4000)
        │                Pipeline control · upload · analysis · auth · admin · Grafana proxy
        ▼
 [8] Dashboard         frontend/  (Next.js, port 3001 in Docker / 3000 in dev)
                         Overview · Detections · Behavioral · AI Insights · Grafana · Admin
```

## Dashboard Pages

| Route | Description |
|-------|-------------|
| `/overview` | Summary cards and traffic timeline |
| `/detections` | CRS rule match table with severity, IP, path, and OWASP tags |
| `/analysis` | Anomaly score timeline and score distribution |
| `/behavioral` | Behavioral heuristic findings (rate spikes, enumeration, etc.) |
| `/ai-insights` | LLM chat — ask questions about the current detection results |
| `/correlation` | Cross-source correlation view |
| `/threat-actor` | IP-level threat actor profiling |
| `/log-statistics` | Request/response statistics and breakdowns |
| `/pipeline` | Trigger and monitor pipeline stages |
| `/projects` | Multi-project management and log upload |
| `/admin` | User management (admin role required) |

## Quick Start

### Docker (recommended)

```bash
# 1. Copy the example env file and add your API key(s)
cp .env.example .env          # then edit .env

# 2. Build and start all services
docker-compose up --build
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:3001 |
| API / Swagger docs | http://localhost:4000/docs |
| Grafana | http://localhost:3000 |
| CRS detector (internal) | http://localhost:8080 |

**Default credentials** (seeded on first startup — change these in production):

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |
| `analyst` | `analyst123` | analyst |

### Local development

```bash
# Python dependencies
pip install -r requirements.txt

# Run pipeline manually (from project root)
python -m core.ingestion.ingest_logs
python -m core.processor.process_logs
python -m core.detection.rule_pipeline

# Start the API
uvicorn api.main:app --port 4000 --reload

# Start the frontend (separate terminal)
cd frontend && npm install && npm run dev
```

> The CRS detection stage requires the `crs-detector` Docker container to be running. You can start it alone with:
> ```bash
> docker-compose up crs-detector
> ```
> and set `CRS_SERVICE_URL=http://localhost:8080` in your `.env`.

## Data Flow

| Stage | Input | Output |
|-------|-------|--------|
| Ingestion | `data/raw_logs/*.log` / `*.gz` | `data/intermediate/raw_entries.json` |
| Parsing | `raw_entries.json` | `data/processed/json/parsed_logs.json` |
| Normalization | `parsed_logs.json` | `data/processed/normalized/normalized_logs.json` |
| CRS Detection | `normalized_logs.json` + live CRS service | `data/detection_results/rule_matches.json` |
| Behavioral | SQLite `logs` table | `data/detection_results/behavioral_results.json` |

All results are also written to the SQLite database at `data/logic.db`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | — | Groq Cloud API key for LLM-powered AI insights |
| `LM_STUDIO_BASE_URL` | `http://host.docker.internal:1234/v1` | Local LM Studio endpoint (alternative to Groq) |
| `LM_STUDIO_MODEL` | `local-model` | Model name to use with LM Studio |
| `CRS_SERVICE_URL` | `http://crs-detector:8080` | URL of the ModSecurity CRS detection container |
| `CRS_PARANOIA_LEVEL` | `1` | CRS paranoia level (1–4; higher = more detections, more false positives) |
| `CRS_BATCH_SIZE` | `500` | Number of log entries sent to CRS per batch |
| `CRS_FLUSH_WAIT` | `10` | Seconds to wait for the CRS audit log to flush after a batch |
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS allowed origins (restrict in production) |
| `GRAFANA_USER` | `admin` | Grafana admin username |
| `GRAFANA_PASSWORD` | `logic1234` | Grafana admin password |
| `API_BASE_URL` | `http://api:4000` | Backend URL used by the Next.js frontend |

## API Endpoints (summary)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login — returns JWT bearer token |
| `GET` | `/api/auth/me` | Current user info |
| `POST` | `/api/upload` | Upload a log file to a project |
| `POST` | `/api/pipeline/run` | Trigger full pipeline for a project |
| `GET` | `/api/analysis/results` | Fetch detection results |
| `GET` | `/api/analysis/behavioral` | Fetch behavioral analysis results |
| `POST` | `/api/analysis/chat` | Send a message to the AI insights chat |
| `GET` | `/api/projects` | List all projects |
| `POST` | `/api/projects` | Create a new project |
| `GET` | `/api/admin/users` | List users (admin only) |

Full interactive documentation is available at **http://localhost:4000/docs** once the API is running.

## Project Structure

```
├── api/                    FastAPI application
│   ├── routes/             Route handlers (auth, pipeline, analysis, chat, admin…)
│   └── services/           LLM and pipeline service wrappers
├── core/                   Detection and processing logic
│   ├── ingestion/          Log file reader / decompressor
│   ├── processor/          Parser and normalizer
│   ├── detection/          CRS processor and rule pipeline
│   ├── behavioral/         Behavioral heuristics engine
│   └── storage/            SQLite schema and query helpers
├── frontend/               Next.js 14 dashboard (App Router)
│   ├── app/(dashboard)/    Dashboard page routes
│   ├── components/         Shared UI components and charts
│   └── lib/                API client, state store, utilities
├── grafana/                Grafana provisioning (dashboards + datasources)
├── data/                   Runtime data (logs, results, SQLite DB — gitignored)
├── docker-compose.yml      Multi-service container definition
└── requirements.txt        Python dependencies
```

## Log Formats Supported

- Apache Combined Log Format
- Nginx default combined log format
- Gzip-compressed variants (`.log.gz`)
