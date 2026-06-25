from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from storage import SpectreDB
import os
import time

def create_api(db: SpectreDB) -> FastAPI:
    """
    Creates and returns a FastAPI application backed by the given SpectreDB.
    """
    app = FastAPI(
        title="Spectre HIDS API",
        description="REST API for querying behavioral events, alerts, and session threat scores.",
        version="7.0"
    )

    # CORS middleware for dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/health")
    def health():
        """Liveness check."""
        return {"status": "ok", "version": "7.0", "timestamp": time.time()}

    @app.get("/api/events")
    def get_events(limit: int = Query(100, ge=1, le=1000),
                   offset: int = Query(0, ge=0)):
        """Query behavioral events, most recent first."""
        events = db.query_events(limit=limit, offset=offset)
        return {"events": events, "count": len(events)}

    @app.get("/api/alerts")
    def get_alerts(limit: int = Query(100, ge=1, le=1000),
                   offset: int = Query(0, ge=0)):
        """Query high-severity threshold alerts, most recent first."""
        alerts = db.query_alerts(limit=limit, offset=offset)
        return {"alerts": alerts, "count": len(alerts)}

    @app.get("/api/sessions")
    def get_sessions(limit: int = Query(100, ge=1, le=1000),
                     offset: int = Query(0, ge=0)):
        """Query session threat scores, highest first."""
        sessions = db.query_sessions(limit=limit, offset=offset)
        return {"sessions": sessions, "count": len(sessions)}

    @app.get("/api/stats")
    def get_stats():
        """Summary statistics from the database."""
        stats = db.get_stats()
        return stats

    # Serve dashboard if it exists
    dashboard_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")
    dashboard_index = os.path.join(dashboard_dir, "index.html")

    @app.get("/", response_class=HTMLResponse)
    def serve_dashboard():
        """Serve the Spectre dashboard."""
        if os.path.exists(dashboard_index):
            with open(dashboard_index, "r") as f:
                return HTMLResponse(content=f.read())
        return HTMLResponse(content="<h1>Spectre HIDS API</h1><p>Dashboard not installed. Visit <a href='/docs'>/docs</a> for API documentation.</p>")

    return app
