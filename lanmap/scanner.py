"""nmap wrapper: build commands, run them, parse the XML output.

Two scan kinds:
  * discovery  - `nmap -sn` host sweep (ARP on the local segment when root).
  * ports      - SYN/connect scan with optional version detection.

Everything is parsed from `-oX -` so we never scrape human-readable output.
"""

from __future__ import annotations

import os
import shlex
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Settings


@dataclass
class PortResult:
    port: int
    protocol: str                 # tcp / udp
    state: str                    # open / closed / filtered / open|filtered
    service: str | None = None    # nmap service name, e.g. "http"
    product: str | None = None    # e.g. "nginx"
    version: str | None = None    # e.g. "1.25.3"
    extrainfo: str | None = None  # e.g. "Ubuntu Linux; protocol 2.0"
    reason: str | None = None     # syn-ack, conn-refused ...
    confidence: int | None = None # nmap service-detection confidence 0-10

    def key(self) -> tuple[int, str]:
        return (self.port, self.protocol)

    def summary(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        label = " ".join(parts) if parts else (self.service or "unknown")
        if self.extrainfo:
            label += f" ({self.extrainfo})"
        return label

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "reason": self.reason,
            "confidence": self.confidence,
            "summary": self.summary(),
        }


@dataclass
class HostResult:
    ip: str
    state: str                       # up / down
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    hostname_source: str | None = None  # PTR / user
    os_guess: str | None = None
    os_accuracy: int | None = None
    latency_ms: float | None = None
    uptime_seconds: int | None = None
    ports: list[PortResult] = field(default_factory=list)
    ports_scanned: bool = False      # True when the scan included a port phase
    extraports: dict[str, int] = field(default_factory=dict)  # state -> count

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state.startswith("open")]

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "state": self.state,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "os_accuracy": self.os_accuracy,
            "latency_ms": self.latency_ms,
            "uptime_seconds": self.uptime_seconds,
            "ports": [p.to_dict() for p in self.ports],
            "ports_scanned": self.ports_scanned,
        }


@dataclass
class ScanResult:
    kind: str                         # discovery / ports
    hosts: list[HostResult]
    started_at: datetime
    finished_at: datetime
    args: str = ""
    targets: list[str] = field(default_factory=list)
    nmap_version: str | None = None
    summary: str | None = None

    @property
    def hosts_up(self) -> list[HostResult]:
        return [h for h in self.hosts if h.state == "up"]


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

def _int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _ts(value: str | None, fallback: datetime | None = None) -> datetime:
    epoch = _int_or_none(value)
    if epoch is not None:
        return datetime.fromtimestamp(epoch, tz=timezone.utc)
    return fallback or datetime.now(timezone.utc)


def _parse_host(node: ET.Element, ports_scanned: bool) -> HostResult | None:
    status = node.find("status")
    state = status.get("state", "unknown") if status is not None else "unknown"

    ip = mac = vendor = None
    for addr in node.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4" and ip is None:
            ip = addr.get("addr")
        elif kind == "ipv6" and ip is None:
            ip = addr.get("addr")
        elif kind == "mac":
            mac = (addr.get("addr") or "").upper() or None
            vendor = addr.get("vendor") or None
    if ip is None:
        return None

    host = HostResult(ip=ip, state=state, mac=mac, vendor=vendor,
                      ports_scanned=ports_scanned)

    hostnames = node.find("hostnames")
    if hostnames is not None:
        for hn in hostnames.findall("hostname"):
            name = hn.get("name")
            if name:
                host.hostname = name
                host.hostname_source = hn.get("type")
                break

    ports_node = node.find("ports")
    if ports_node is not None:
        for extra in ports_node.findall("extraports"):
            count = _int_or_none(extra.get("count"))
            if count is not None:
                host.extraports[extra.get("state", "unknown")] = count
        for pnode in ports_node.findall("port"):
            portid = _int_or_none(pnode.get("portid"))
            if portid is None:
                continue
            pstate = pnode.find("state")
            svc = pnode.find("service")
            pr = PortResult(
                port=portid,
                protocol=pnode.get("protocol", "tcp"),
                state=pstate.get("state", "unknown") if pstate is not None else "unknown",
                reason=pstate.get("reason") if pstate is not None else None,
            )
            if svc is not None:
                pr.service = svc.get("name") or None
                pr.product = svc.get("product") or None
                pr.version = svc.get("version") or None
                pr.extrainfo = svc.get("extrainfo") or None
                pr.confidence = _int_or_none(svc.get("conf"))
            host.ports.append(pr)

    os_node = node.find("os")
    if os_node is not None:
        best = None
        for match in os_node.findall("osmatch"):
            acc = _int_or_none(match.get("accuracy")) or 0
            if best is None or acc > best[1]:
                best = (match.get("name"), acc)
        if best:
            host.os_guess, host.os_accuracy = best

    times = node.find("times")
    if times is not None:
        srtt = _int_or_none(times.get("srtt"))
        if srtt is not None:
            host.latency_ms = round(srtt / 1000.0, 2)

    uptime = node.find("uptime")
    if uptime is not None:
        host.uptime_seconds = _int_or_none(uptime.get("seconds"))

    return host


def parse_nmap_xml(xml_text: str, kind: str = "discovery") -> ScanResult:
    """Parse `nmap -oX -` output. Tolerates a truncated document."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # nmap killed mid-run leaves an unterminated <nmaprun>; salvage it.
        root = ET.fromstring(xml_text + "</nmaprun>")

    started = _ts(root.get("start"))
    finished = started
    summary = None
    runstats = root.find("runstats")
    if runstats is not None:
        fin = runstats.find("finished")
        if fin is not None:
            finished = _ts(fin.get("time"), started)
            summary = fin.get("summary")

    ports_scanned = kind == "ports"
    hosts: list[HostResult] = []
    for hnode in root.findall("host"):
        parsed = _parse_host(hnode, ports_scanned)
        if parsed is not None:
            hosts.append(parsed)

    return ScanResult(
        kind=kind,
        hosts=hosts,
        started_at=started,
        finished_at=finished,
        args=root.get("args", ""),
        nmap_version=root.get("version"),
        summary=summary,
    )


# --------------------------------------------------------------------------- #
# Command building / running
# --------------------------------------------------------------------------- #

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # Windows
        return False


def _port_spec_args(spec: str) -> list[str]:
    spec = (spec or "").strip()
    if spec.startswith("top"):
        n = spec[3:].strip() or "1000"
        return ["--top-ports", n]
    if spec in ("", "all", "-"):
        return ["-p-"]
    return ["-p", spec]


def build_discovery_cmd(settings: Settings, targets: list[str]) -> list[str]:
    cmd = [settings.nmap_path, "-sn", "-n", f"-{settings.nmap_timing}", "-oX", "-"]
    if is_root():
        cmd.append("-PR")          # ARP ping; most reliable on a LAN
    else:
        cmd += ["-PE", "-PS22,80,443,8080", "-PA80,443"]
    if settings.interface:
        cmd += ["-e", settings.interface]
    cmd += targets
    return cmd


def build_port_scan_cmd(settings: Settings, targets: list[str], deep: bool = False,
                        ports: str | None = None, os_detect: bool | None = None) -> list[str]:
    cmd = [settings.nmap_path, "-oX", "-", f"-{settings.nmap_timing}",
           "--host-timeout", f"{settings.host_timeout_seconds}s", "-Pn"]
    cmd.append("-sS" if is_root() else "-sT")
    cmd += _port_spec_args(ports or (settings.deep_ports if deep else settings.quick_ports))
    if settings.version_detection:
        cmd += ["-sV"]
        if not deep:
            cmd += ["--version-light"]
    if os_detect is None:
        os_detect = deep
    if os_detect and is_root():
        cmd += ["-O", "--osscan-limit"]
    if settings.interface:
        cmd += ["-e", settings.interface]
    cmd += ["--max-hostgroup", str(max(1, settings.max_parallel_hosts))]
    cmd += targets
    return cmd


class NmapError(RuntimeError):
    pass


def run_nmap(cmd: list[str], timeout: int | None = None) -> str:
    """Run nmap and return its XML stdout. Raises NmapError on failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as exc:
        raise NmapError(f"nmap not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        if partial and "<nmaprun" in partial:
            return partial
        raise NmapError(f"nmap timed out after {timeout}s: {shlex.join(cmd)}") from exc
    if proc.returncode != 0 and "<nmaprun" not in proc.stdout:
        raise NmapError(f"nmap exited {proc.returncode}: {proc.stderr.strip()[:500]}")
    return proc.stdout


def nmap_version(nmap_path: str = "nmap") -> str | None:
    try:
        out = subprocess.run([nmap_path, "--version"], capture_output=True, text=True,
                             timeout=10, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    first = out.strip().splitlines()[0] if out.strip() else ""
    return first or None
