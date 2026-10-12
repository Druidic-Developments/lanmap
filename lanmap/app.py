"""FastAPI application: REST API + static dashboard."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, localports
from .config import Settings
from .db import Store
from .manager import ScanManager

STATIC_DIR = Path(__file__).parent / "static"


class DeviceUpdate(BaseModel):
    label: str | None = None
    device_type: str | None = None
    notes: str | None = None
    skip_ports: bool | None = None


class PortScanRequest(BaseModel):
    device_ids: list[int] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    deep: bool = False
    ports: str | None = None     # explicit nmap port spec, overrides quick/deep default
    all_online: bool = False


def create_app(settings: Settings | None = None, store: Store | None = None,
               manager: ScanManager | None = None, start_workers: bool = True) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or Store(settings.db_path)
    manager = manager or ScanManager(settings, store)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if start_workers:
            manager.start()
        yield
        manager.stop()
        store.close()

    app = FastAPI(title="lanmap", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.store = store
    app.state.manager = manager

    # ------------------------------------------------------------------ pages
    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    # ------------------------------------------------------------------- meta
    @app.get("/api/status")
    def status():
        return {
            "version": __version__,
            "settings": settings.public_dict(),
            "scanner": manager.status(),
            "stats": store.stats(),
        }

    # ---------------------------------------------------------------- devices
    @app.get("/api/devices")
    def devices():
        return store.list_devices()

    @app.get("/api/devices/{device_id}")
    def device(device_id: int):
        d = store.get_device(device_id)
        if not d:
            raise HTTPException(404, "device not found")
        return d

    @app.patch("/api/devices/{device_id}")
    def update_device(device_id: int, body: DeviceUpdate):
        fields = body.model_dump(exclude_unset=True)
        d = store.update_device(device_id, fields)
        if not d:
            raise HTTPException(404, "device not found")
        return d

    @app.delete("/api/devices/{device_id}")
    def delete_device(device_id: int):
        if not store.delete_device(device_id):
            raise HTTPException(404, "device not found")
        return {"deleted": device_id}

    # ------------------------------------------------------------------ ports
    @app.get("/api/ports")
    def ports():
        return store.all_ports()

    @app.get("/api/localports")
    def local_ports():
        sockets, error, hint = localports.list_listening_sockets()
        return {"host": settings.local_ip, "sockets": [s.to_dict() for s in sockets],
                "error": error, "hint": hint}

    # ----------------------------------------------------------------- events
    @app.get("/api/events")
    def events(limit: int = 200, since_id: int | None = None, kinds: str | None = None):
        kind_list = [k for k in (kinds or "").split(",") if k] or None
        return store.list_events(limit=min(limit, 1000), since_id=since_id, kinds=kind_list)

    @app.get("/api/scans")
    def scans(limit: int = 50):
        return store.list_scans(limit=min(limit, 500))

    # -------------------------------------------------------------------- map
    @app.get("/api/map")
    def map_data():
        return store.map_data(settings.gateway, settings.local_ip)

    # ------------------------------------------------------------------ scans
    @app.post("/api/scan/discovery")
    def scan_discovery():
        job = manager.enqueue_discovery(requested_by="user")
        if job is None:
            raise HTTPException(400, manager.status().get("last_error") or "cannot start scan")
        return {"queued": job.to_dict()}

    @app.post("/api/scan/ports")
    def scan_ports(body: PortScanRequest):
        targets: list[str] = list(body.ips)
        if body.all_online:
            job = manager.enqueue_port_scan_all_online(deep=body.deep, requested_by="user")
            if job is None:
                raise HTTPException(400, "no online devices to scan")
            return {"queued": job.to_dict()}
        for did in body.device_ids:
            d = store.get_device(did)
            if d and d.get("ip"):
                if d["skip_ports"]:
                    continue
                targets.append(d["ip"])
        if not targets:
            raise HTTPException(400, "no scannable targets (check skip flags)")
        job = manager.enqueue_port_scan(sorted(set(targets)), deep=body.deep,
                                        ports=body.ports, requested_by="user")
        if job is None:
            raise HTTPException(400, "all targets are in the skip list")
        return {"queued": job.to_dict()}

    @app.exception_handler(Exception)
    async def unhandled(_, exc: Exception):
        logging.getLogger("lanmap").exception("unhandled error")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app
