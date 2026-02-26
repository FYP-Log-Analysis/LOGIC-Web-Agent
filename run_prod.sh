#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_prod.sh — LOGIC Web Agent production launcher (no Docker)
#
# Usage:
#   chmod +x run_prod.sh
#   ./run_prod.sh
#
# Prerequisites:
#   • Copy .env.example → .env and fill in ALL values (JWT_SECRET_KEY, GROQ_API_KEY …)
#   • Python 3.11+ and pip available in PATH
#   • (Optional) Run behind Nginx for HTTPS — see README.md production section
#
# What it does:
#   1. Validates required env vars are set
#   2. Activates .venv (creates and installs deps if missing)
#   3. Starts FastAPI with uvicorn (2 workers, no --reload)
#   4. Starts Streamlit in headless mode
#   5. Traps Ctrl+C / SIGTERM to cleanly stop both
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${CYAN}[prod]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC}   $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}   $*"; }
die()  { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

# ── 1. Load .env ──────────────────────────────────────────────────────────────
if [ -f ".env" ]; then
    log "Loading .env …"
    set -o allexport
    # shellcheck disable=SC1091
    source .env
    set +o allexport
    ok ".env loaded"
else
    die ".env file not found. Copy .env.example to .env and fill in all values."
fi

# ── 2. Validate required env vars ─────────────────────────────────────────────
[[ -z "${JWT_SECRET_KEY:-}" ]]  && die "JWT_SECRET_KEY is not set in .env"
[[ "${JWT_SECRET_KEY}" == "CHANGE-ME-"* ]] && die "JWT_SECRET_KEY still has the placeholder value. Generate a real key."
[[ -z "${GROQ_API_KEY:-}" ]]   && warn "GROQ_API_KEY is not set — AI features will be disabled."

ok "Environment validated."

# ── 3. Virtual env ────────────────────────────────────────────────────────────
VENV=".venv"
if [ ! -d "$VENV" ]; then
    log "Creating virtual environment …"
    python3 -m venv "$VENV"
fi

source "$VENV/bin/activate"

log "Installing / upgrading dependencies …"
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
pip install --quiet -r api/requirements.txt
ok "Dependencies ready."

# ── 4. Ensure data directories exist ─────────────────────────────────────────
mkdir -p data/raw_logs data/intermediate data/processed/normalized \
         data/detection_results data/crs_audit data/projects

# ── 5. Export runtime env vars ────────────────────────────────────────────────
export PYTHONPATH="$SCRIPT_DIR"
export API_BASE_URL="${API_BASE_URL:-http://localhost:4000}"
export DATA_ROOT="${DATA_ROOT:-$SCRIPT_DIR/data}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:8501}"

# ── 6. Start FastAPI (production mode — 2 workers, no hot-reload) ─────────────
log "Starting FastAPI on :4000 (2 workers) …"
uvicorn api.main:app \
    --host 0.0.0.0 \
    --port 4000 \
    --workers 2 \
    --log-level warning \
    --access-log &
API_PID=$!

sleep 2

# ── 7. Start Streamlit (headless, no browser pop-up) ─────────────────────────
log "Starting Streamlit on :8501 …"
streamlit run dashboard/main.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --server.enableCORS false \
    --server.enableXsrfProtection true \
    --browser.gatherUsageStats false &
DASH_PID=$!

# ── 8. Print summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  LOGIC Web Agent — PRODUCTION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard  : ${CYAN}http://$(hostname -I | awk '{print $1}'):8501${NC}"
echo -e "  API        : ${CYAN}http://$(hostname -I | awk '{print $1}'):4000${NC}"
echo -e "  API docs   : ${CYAN}http://$(hostname -I | awk '{print $1}'):4000/docs${NC}"
echo -e ""
echo -e "  API PID    : ${API_PID}"
echo -e "  Dash PID   : ${DASH_PID}"
echo -e ""
echo -e "  Press ${RED}Ctrl+C${NC} or send SIGTERM to stop both services"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── 9. Wait and clean up ──────────────────────────────────────────────────────
cleanup() {
    echo ""
    log "Received shutdown signal — stopping services …"
    kill "$API_PID" "$DASH_PID" 2>/dev/null || true
    wait "$API_PID" "$DASH_PID" 2>/dev/null || true
    ok "Services stopped. Goodbye."
}
trap cleanup INT TERM

wait
