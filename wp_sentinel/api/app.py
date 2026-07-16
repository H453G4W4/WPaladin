"""FastAPI application: REST + WebSocket API and the served dashboard.

Endpoints (all under ``/api/v1`` except the dashboard root and WS):

* ``POST   /api/v1/scans``               start a scan (requires authorization)
* ``GET    /api/v1/scans``               list scans
* ``GET    /api/v1/scans/{id}``          scan status + summary
* ``GET    /api/v1/scans/{id}/findings`` full findings
* ``GET    /api/v1/scans/{id}/report``   rendered report (json/html/csv)
* ``GET    /api/v1/checks``              registered checks
* ``GET    /api/v1/profiles``            scan profiles
* ``WS     /api/v1/scans/{id}/ws``       live status stream
* ``GET    /``                           browser dashboard

The authorization gate is enforced here too: a scan request without
``authorized: true`` is rejected with HTTP 403. WP-Sentinel only performs
non-destructive checks — the API exposes no exploitation capability.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from .. import __version__
from ..checks.base import all_checks
from ..core.profile import PROFILES, get_profile
from ..core.scanner import Scanner
from ..core.target import AuthorizationError, Target
from ..report import render
from ..store import ScanRecord, ScanStatus, ScanStore

_DASHBOARD = Path(__file__).parent / "dashboard.html"
_TERMINAL = {ScanStatus.COMPLETED, ScanStatus.FAILED}


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL or hostname.")
    profile: str = Field("standard", description="Scan profile name.")
    authorized: bool = Field(
        False,
        description="Must be true: assert you are authorized to test this target.",
    )


def create_app(store: ScanStore | None = None, *, transport=None) -> FastAPI:
    """Build the FastAPI app.

    ``transport`` (an ``httpx`` transport) is injected into scans; tests use a
    mock transport so the API can be exercised without touching the network.
    """
    app = FastAPI(title="WP-Sentinel", version=__version__)
    app.state.store = store or ScanStore()
    app.state.scanner = Scanner()
    app.state.transport = transport

    async def _execute(scan_id: str, target: Target, profile_name: str) -> None:
        st: ScanStore = app.state.store
        await st.set_running(scan_id)
        try:
            profile = get_profile(profile_name)
            result = await app.state.scanner.scan(
                target, profile, transport=app.state.transport
            )
            await st.set_result(scan_id, result)
        except Exception as exc:  # noqa: BLE001 - surface any failure to the record
            await st.set_failed(scan_id, repr(exc))

    @app.post("/api/v1/scans", status_code=201)
    async def start_scan(req: ScanRequest) -> dict:
        if not req.authorized:
            raise HTTPException(
                status_code=403,
                detail="Authorization not acknowledged. Set authorized=true to "
                "confirm you may test this target.",
            )
        if req.profile not in PROFILES:
            raise HTTPException(status_code=400, detail=f"Unknown profile: {req.profile}")
        try:
            target = Target.parse(req.url, authorized=True)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        record = await app.state.store.create(target.base_url, req.profile)
        asyncio.create_task(_execute(record.id, target, req.profile))
        return record.summary()

    @app.get("/api/v1/scans")
    async def list_scans() -> list[dict]:
        return [r.summary() for r in await app.state.store.list()]

    @app.get("/api/v1/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict:
        return (await _require(app, scan_id)).summary()

    @app.get("/api/v1/scans/{scan_id}/findings")
    async def get_findings(scan_id: str) -> dict:
        record = await _require(app, scan_id)
        if record.result is None:
            return {"id": scan_id, "status": record.status.value, "findings": []}
        return {
            "id": scan_id,
            "status": record.status.value,
            "findings": [f.to_dict() for f in record.result.sorted_findings()],
        }

    @app.get("/api/v1/scans/{scan_id}/report")
    async def get_report(scan_id: str, format: str = "json") -> Response:
        record = await _require(app, scan_id)
        if record.result is None:
            raise HTTPException(status_code=409, detail="Scan not completed yet.")
        try:
            body = render(format, record.result)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        media = {"json": "application/json", "html": "text/html", "csv": "text/csv"}[
            format
        ]
        return Response(content=body, media_type=media)

    @app.get("/api/v1/checks")
    async def list_checks() -> list[dict]:
        return [
            {
                "id": c.id,
                "name": c.name,
                "active_probe": c.requires_active_probes,
            }
            for c in all_checks()
        ]

    @app.get("/api/v1/profiles")
    async def list_profiles() -> list[dict]:
        return [
            {
                "name": p.name,
                "concurrency": p.concurrency,
                "delay_seconds": p.delay_seconds,
                "active_probes": p.active_probes,
                "description": p.description,
            }
            for p in PROFILES.values()
        ]

    @app.websocket("/api/v1/scans/{scan_id}/ws")
    async def scan_ws(websocket: WebSocket, scan_id: str) -> None:
        await websocket.accept()
        try:
            while True:
                record = await app.state.store.get(scan_id)
                if record is None:
                    await websocket.send_json({"error": "not found"})
                    return
                await websocket.send_json(record.summary())
                if record.status in _TERMINAL:
                    return
                await asyncio.sleep(0.5)
        except WebSocketDisconnect:
            return

    @app.get("/api/v1/health")
    async def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> str:
        if _DASHBOARD.exists():
            return _DASHBOARD.read_text(encoding="utf-8")
        return "<h1>WP-Sentinel</h1><p>Dashboard asset missing.</p>"

    return app


async def _require(app: FastAPI, scan_id: str) -> ScanRecord:
    record = await app.state.store.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return record
