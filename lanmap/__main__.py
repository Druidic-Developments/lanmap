"""`python -m lanmap` — run the dashboard server."""

from __future__ import annotations

import logging
import os

import uvicorn

from .app import create_app
from .config import Settings


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LANMAP_LOG", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    settings = Settings.from_env()
    log = logging.getLogger("lanmap")
    log.info("subnets=%s gateway=%s iface=%s local_ip=%s db=%s",
             settings.subnets, settings.gateway, settings.interface, settings.local_ip,
             settings.db_path)
    if not settings.subnets:
        log.warning("No subnet detected. Set LANMAP_SUBNETS=192.168.1.0/24 (and use host "
                    "networking in Docker).")
    app = create_app(settings)
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port, log_level="info")


if __name__ == "__main__":
    main()
