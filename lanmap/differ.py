"""Pure change-detection logic. No I/O, so it's trivially testable.

`diff_device` compares a stored device row with a fresh HostResult.
`diff_ports` compares stored open ports with the ports from a new scan.
Both return a list of Event records the store persists and the UI shows.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .scanner import HostResult, PortResult

OPEN_STATES = ("open", "open|filtered")


@dataclass
class Event:
    kind: str
    message: str
    details: dict = field(default_factory=dict)
    severity: str = "info"   # info / notice / warn

    def to_dict(self) -> dict:
        return {"kind": self.kind, "message": self.message,
                "details": self.details, "severity": self.severity}


def _label(device: dict | None, host: HostResult) -> str:
    if device:
        for key in ("label", "hostname"):
            if device.get(key):
                return f"{device[key]} ({host.ip})"
    if host.hostname:
        return f"{host.hostname} ({host.ip})"
    return host.ip


def diff_device(device: dict | None, host: HostResult) -> list[Event]:
    """Events caused by seeing `host` given the previously stored `device` (or None)."""
    events: list[Event] = []
    name = _label(device, host)

    if device is None:
        vendor = f" [{host.vendor}]" if host.vendor else ""
        events.append(Event("device_new", f"New device {name}{vendor}",
                            {"ip": host.ip, "mac": host.mac, "vendor": host.vendor},
                            severity="notice"))
        return events

    if device.get("status") == "offline":
        events.append(Event("device_online", f"{name} is back online",
                            {"ip": host.ip, "mac": host.mac}))

    old_ip = device.get("ip")
    if old_ip and old_ip != host.ip:
        events.append(Event("ip_changed", f"{name} moved from {old_ip} to {host.ip}",
                            {"old": old_ip, "new": host.ip}))

    old_hn = device.get("hostname")
    if host.hostname and old_hn != host.hostname:
        events.append(Event("hostname_changed",
                            f"{host.ip} hostname changed: {old_hn or '-'} -> {host.hostname}",
                            {"old": old_hn, "new": host.hostname}))

    old_mac = device.get("mac")
    if host.mac and old_mac and old_mac != host.mac:
        events.append(Event("mac_changed",
                            f"{name} MAC changed: {old_mac} -> {host.mac}",
                            {"old": old_mac, "new": host.mac}, severity="warn"))
    return events


def _open_ports(ports: list[PortResult]) -> dict[tuple[int, str], PortResult]:
    return {p.key(): p for p in ports if p.state in OPEN_STATES}


def diff_ports(device_label: str, old_ports: dict[tuple[int, str], dict],
               new_ports: list[PortResult]) -> list[Event]:
    """Compare stored open ports (keyed (port, proto) -> row dict) with scan output."""
    events: list[Event] = []
    new_open = _open_ports(new_ports)

    for key, pr in sorted(new_open.items()):
        old = old_ports.get(key)
        if old is None:
            events.append(Event(
                "port_opened",
                f"{device_label}: {pr.port}/{pr.protocol} opened ({pr.summary()})",
                {"port": pr.port, "protocol": pr.protocol, "service": pr.service,
                 "summary": pr.summary()},
                severity="notice"))
            continue
        old_summary = _row_summary(old)
        new_summary = pr.summary()
        if old_summary != new_summary and pr.product:
            # Only flag when the new scan actually fingerprinted something;
            # a quick scan without -sV shouldn't "downgrade" a known service.
            events.append(Event(
                "service_changed",
                f"{device_label}: {pr.port}/{pr.protocol} now {new_summary} (was {old_summary})",
                {"port": pr.port, "protocol": pr.protocol,
                 "old": old_summary, "new": new_summary}))

    for key, old in sorted(old_ports.items()):
        if key not in new_open:
            port, proto = key
            events.append(Event(
                "port_closed",
                f"{device_label}: {port}/{proto} closed (was {_row_summary(old)})",
                {"port": port, "protocol": proto, "summary": _row_summary(old)}))
    return events


def _row_summary(row: dict) -> str:
    parts = [p for p in (row.get("product"), row.get("version")) if p]
    label = " ".join(parts) if parts else (row.get("service") or "unknown")
    if row.get("extrainfo"):
        label += f" ({row['extrainfo']})"
    return label


def merge_port_rows(old: dict | None, new: PortResult) -> dict:
    """Combine a stored port row with a fresh result, keeping the richer fingerprint
    when the new scan didn't do version detection."""
    row = {
        "port": new.port, "protocol": new.protocol, "state": new.state,
        "service": new.service, "product": new.product, "version": new.version,
        "extrainfo": new.extrainfo, "reason": new.reason, "confidence": new.confidence,
    }
    if old and not new.product and old.get("product"):
        row["product"] = old.get("product")
        row["version"] = old.get("version")
        row["extrainfo"] = old.get("extrainfo")
        row["confidence"] = old.get("confidence")
        if not row["service"]:
            row["service"] = old.get("service")
    return row
