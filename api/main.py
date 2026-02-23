from fastapi import FastAPI
from api.routes import pipeline, upload, analysis
from api.routes.search import router as search_router, grafana as grafana_router
from analysis.sqlite_store import init_db

app = FastAPI(
    title="LOGIC Web Agent API",
    description="Web server log forensics — ingest, analyse, and interpret access/error logs",
    version="1.0",
)

# Ensure SQLite schema exists on startup
@app.on_event("startup")
def on_startup() -> None:
    init_db()

app.include_router(pipeline.router, prefix="/api/pipeline")
app.include_router(upload.router,   prefix="/api")
app.include_router(analysis.router, prefix="/api/analysis")
app.include_router(search_router,   prefix="/api")
app.include_router(grafana_router,  prefix="/api")


@app.get("/")
def root():
    return {"message": "LOGIC Web Agent API", "status": "running", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4000)
