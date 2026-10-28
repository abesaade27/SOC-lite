"""FastAPI Application factory and lifespan setup for SOC-Lite."""

import asyncio
from contextlib import asynccontextmanager
import os
from typing import Any, AsyncGenerator, Dict
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from server.config import settings
from server.db import Database
from server.detections.engine import engine
from server.retention import run_retention_loop
from server.routers import alerts, events, ingest, stats, ws

DB_INSTANCE = Database(settings.DB_PATH)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # 1. Initialize SQLite tables & WAL mode
    await DB_INSTANCE.init_db()
    app.state.db = DB_INSTANCE

    # 2. Warm up detection engine state with recent events
    try:
        warmup_events = await DB_INSTANCE.get_recent_events_for_warmup(minutes=10)
        engine.warmup(warmup_events)
    except Exception as e:
        pass

    # 3. Start background data retention worker
    retention_task = asyncio.create_task(run_retention_loop(settings.DB_PATH, check_interval_hours=1))

    yield

    # Shutdown
    retention_task.cancel()
    try:
        await retention_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="SOC-Lite Ingest & Detection API",
    version="1.0.0",
    lifespan=lifespan,
)

# Strict CORS: only same-origin/localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next: Any) -> Response:
    response: Response = await call_next(request)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws://127.0.0.1:* ws://localhost:* http://127.0.0.1:* http://localhost:*; "
        "img-src 'self' data:; "
        "font-src 'self';"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# Include API Routers
app.include_router(ingest.router)
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(ws.router)


@app.get("/healthz")
async def healthz() -> Dict[str, Any]:
    return await DB_INSTANCE.get_health()


# Dashboard static files & index mounting
dashboard_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_dir):
    app.mount("/static", StaticFiles(directory=dashboard_dir), name="static")


@app.get("/")
async def serve_index() -> FileResponse:
    index_file = os.path.join(dashboard_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return Response(content="SOC-Lite Dashboard is loading...", media_type="text/plain")
