"""Runtime configuration, read from environment variables.

Everything has a sane default so `docker compose up` works with no .env file.
Subnet and gateway are autodetected from the container's routing table when
not set explicitly (requires host networking to see the real LAN).
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in re.split(r"[,\s]+", raw) if item.strip()]


def detect_default_route() -> tuple[str | None, str | None, str | None]:
    """Return (interface, gateway_ip, local_ip) from `ip route`, or Nones."""
    try:
        out = subprocess.run(
            ["ip", "-4", "route", "show", "default"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None, None, None
    match = re.search(r"default via (\S+) dev (\S+)", out)
    if not match:
        return None, None, None
    gateway, iface = match.group(1), match.group(2)
    local_ip = None
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
        m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", out)
        if m2:
            local_ip = m2.group(1)
    except (OSError, subprocess.SubprocessError):
        pass
    return iface, gateway, local_ip


def detect_subnets() -> list[str]:
    """Subnet(s) of the default-route interface, as CIDR strings."""
    _, _, local = detect_default_route()
    if not local:
        return []
    net = ipaddress.ip_interface(local).network
    return [str(net)]


@dataclass
class Settings:
    subnets: list[str] = field(default_factory=list)
    gateway: str | None = None
    interface: str | None = None
    local_ip: str | None = None
    db_path: str = "/data/lanmap.db"
    bind_host: str = "0.0.0.0"
    bind_port: int = 8080
    scan_interval_minutes: int = 30          # 0 disables the scheduler
    port_scan_interval_minutes: int = 360    # 0 disables scheduled port scans
    quick_ports: str = "top1000"             # nmap --top-ports 1000, or explicit list
    deep_ports: str = "1-65535"
    version_detection: bool = True
    nmap_timing: str = "T4"
    host_timeout_seconds: int = 300
    max_parallel_hosts: int = 4
    skip_hosts: list[str] = field(default_factory=list)   # fragile IoT etc.
    offline_after_misses: int = 2            # discovery misses before "offline"
    nmap_path: str = "nmap"

    @classmethod
    def from_env(cls) -> "Settings":
        iface, gw, local = detect_default_route()
        subnets = _env_list("LANMAP_SUBNETS") or detect_subnets()
        return cls(
            subnets=subnets,
            gateway=os.environ.get("LANMAP_GATEWAY") or gw,
            interface=os.environ.get("LANMAP_INTERFACE") or iface,
            local_ip=local.split("/")[0] if local else None,
            db_path=os.environ.get("LANMAP_DB", "/data/lanmap.db"),
            bind_host=os.environ.get("LANMAP_BIND", "0.0.0.0"),
            bind_port=_env_int("LANMAP_PORT", 8080),
            scan_interval_minutes=_env_int("LANMAP_SCAN_INTERVAL", 30),
            port_scan_interval_minutes=_env_int("LANMAP_PORT_SCAN_INTERVAL", 360),
            quick_ports=os.environ.get("LANMAP_QUICK_PORTS", "top1000"),
            deep_ports=os.environ.get("LANMAP_DEEP_PORTS", "1-65535"),
            version_detection=_env_bool("LANMAP_VERSION_DETECTION", True),
            nmap_timing=os.environ.get("LANMAP_TIMING", "T4"),
            host_timeout_seconds=_env_int("LANMAP_HOST_TIMEOUT", 300),
            max_parallel_hosts=_env_int("LANMAP_PARALLEL", 4),
            skip_hosts=_env_list("LANMAP_SKIP_HOSTS"),
            offline_after_misses=_env_int("LANMAP_OFFLINE_AFTER", 2),
            nmap_path=os.environ.get("LANMAP_NMAP", "nmap"),
        )

    def public_dict(self) -> dict:
        return {
            "subnets": self.subnets,
            "gateway": self.gateway,
            "interface": self.interface,
            "local_ip": self.local_ip,
            "scan_interval_minutes": self.scan_interval_minutes,
            "port_scan_interval_minutes": self.port_scan_interval_minutes,
            "quick_ports": self.quick_ports,
            "deep_ports": self.deep_ports,
            "version_detection": self.version_detection,
            "skip_hosts": self.skip_hosts,
            "offline_after_misses": self.offline_after_misses,
        }
