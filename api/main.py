from fastapi import FastAPI
from api.routes import pipeline, upload, analysis

app = FastAPI(
    title="LOGIC Web Agent API",
    description="Web server log forensics — ingest, analyse, and interpret access/error logs",
    version="1.0",
)

app.include_router(pipeline.router, prefix="/api/pipeline")
app.include_router(upload.router,   prefix="/api")
app.include_router(analysis.router, prefix="/api/analysis")


@app.get("/")
def root():
    return {"message": "LOGIC Web Agent API", "status": "running", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=4000)
