"""SQLite store for devices, their open ports, scan runs and change events."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from .differ import OPEN_STATES, Event, diff_device, diff_ports, merge_port_rows
from .scanner import HostResult, ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY,
    identity      TEXT NOT NULL UNIQUE,       -- MAC when known, else "ip:<addr>"
    mac           TEXT,
    ip            TEXT,
    subnet        TEXT,
    hostname      TEXT,
    vendor        TEXT,
    os_guess      TEXT,
    os_accuracy   INTEGER,
    latency_ms    REAL,
    label         TEXT,                       -- user-set
    device_type   TEXT,                       -- user-set (router, server, phone...)
    notes         TEXT,                       -- user-set
    skip_ports    INTEGER NOT NULL DEFAULT 0, -- user flag: never port-scan
    status        TEXT NOT NULL DEFAULT 'online',
    misses        INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    last_port_scan TEXT,
    last_port_scan_kind TEXT
);
CREATE INDEX IF NOT EXISTS devices_ip ON devices(ip);

CREATE TABLE IF NOT EXISTS ports (
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT NOT NULL,
    state       TEXT NOT NULL,
    service     TEXT,
    product     TEXT,
    version     TEXT,
    extrainfo   TEXT,
    reason      TEXT,
    confidence  INTEGER,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    PRIMARY KEY (device_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running',
    targets     TEXT,
    args        TEXT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    hosts_up    INTEGER,
    summary     TEXT,
    error       TEXT,
    event_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    scan_id    INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    device_id  INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'info',
    message    TEXT NOT NULL,
    details    TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
"""

USER_EDITABLE = ("label", "device_type", "notes", "skip_ports")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def identity_for(host: HostResult) -> str:
    return host.mac if host.mac else f"ip:{host.ip}"


def subnet_for(ip: str, subnets: list[str]) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for cidr in subnets:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return cidr
        except ValueError:
            continue
    # Fall back to a /24 so devices outside configured subnets still group.
    if addr.version == 4:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return None


class Store:
    def __init__(self, path: str):
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ scans
    def start_scan(self, kind: str, targets: list[str], args: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO scans (kind, targets, args, started_at) VALUES (?,?,?,?)",
                (kind, json.dumps(targets), args, _now()))
            self._conn.commit()
            return int(cur.lastrowid)

    def finish_scan(self, scan_id: int, status: str, hosts_up: int | None = None,
                    summary: str | None = None, error: str | None = None,
                    args: str | None = None, event_count: int = 0) -> None:
        with self._lock:
            self._conn.execute(
                """UPDATE scans SET status=?, finished_at=?, hosts_up=?, summary=?, error=?,
                   args=COALESCE(?, args), event_count=? WHERE id=?""",
                (status, _now(), hosts_up, summary, error, args, event_count, scan_id))
            self._conn.commit()

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["targets"] = json.loads(d["targets"]) if d.get("targets") else []
            out.append(d)
        return out

    # ---------------------------------------------------------------- devices
    def _device_by_identity(self, identity: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM devices WHERE identity=?", (identity,)).fetchone()
        return dict(row) if row else None

    def _device_by_ip(self, ip: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE ip=? ORDER BY last_seen DESC LIMIT 1", (ip,)).fetchone()
        return dict(row) if row else None

    def _add_event(self, ev: Event, scan_id: int | None, device_id: int | None) -> None:
        self._conn.execute(
            "INSERT INTO events (ts, scan_id, device_id, kind, severity, message, details) "
            "VALUES (?,?,?,?,?,?,?)",
            (_now(), scan_id, device_id, ev.kind, ev.severity, ev.message,
             json.dumps(ev.details)))

    def _upsert_host(self, host: HostResult, scan_id: int | None,
                     subnets: list[str], seen_at: str) -> tuple[int, list[Event]]:
        """Insert or update a device from a scan result; returns (device_id, events)."""
        identity = identity_for(host)
        device = self._device_by_identity(identity)
        if device is None and host.mac:
            # A device first seen without a MAC (e.g. scanned by IP only) now has one.
            legacy = self._device_by_identity(f"ip:{host.ip}")
            if legacy:
                self._conn.execute("UPDATE devices SET identity=?, mac=? WHERE id=?",
                                   (identity, host.mac, legacy["id"]))
                device = self._device_by_identity(identity)
        if device is None and not host.mac:
            # No MAC in this scan (port scans of remote subnets); match by IP.
            device = self._device_by_ip(host.ip)

        events = diff_device(device, host)
        subnet = subnet_for(host.ip, subnets)
        if device is None:
            cur = self._conn.execute(
                """INSERT INTO devices (identity, mac, ip, subnet, hostname, vendor, os_guess,
                   os_accuracy, latency_ms, status, misses, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,'online',0,?,?)""",
                (identity, host.mac, host.ip, subnet, host.hostname, host.vendor,
                 host.os_guess, host.os_accuracy, host.latency_ms, seen_at, seen_at))
            device_id = int(cur.lastrowid)
        else:
            device_id = device["id"]
            self._conn.execute(
                """UPDATE devices SET ip=?, subnet=?, hostname=COALESCE(?, hostname),
                   vendor=COALESCE(?, vendor), os_guess=COALESCE(?, os_guess),
                   os_accuracy=COALESCE(?, os_accuracy), latency_ms=COALESCE(?, latency_ms),
                   mac=COALESCE(?, mac), status='online', misses=0, last_seen=?
                   WHERE id=?""",
                (host.ip, subnet, host.hostname, host.vendor, host.os_guess,
                 host.os_accuracy, host.latency_ms, host.mac, seen_at, device_id))
        for ev in events:
            self._add_event(ev, scan_id, device_id)
        return device_id, events

    def record_discovery(self, result: ScanResult, subnets: list[str],
                         scan_id: int | None = None, offline_after: int = 2) -> list[Event]:
        """Apply a discovery sweep: upsert hosts that are up, age out the rest."""
        seen_at = _iso(result.finished_at)
        events: list[Event] = []
        with self._lock:
            seen_ids: set[int] = set()
            for host in result.hosts_up:
                device_id, evs = self._upsert_host(host, scan_id, subnets, seen_at)
                seen_ids.add(device_id)
                events.extend(evs)

            # Only age devices whose IP falls inside a swept target.
            targets = [ipaddress.ip_network(t, strict=False) for t in result.targets
                       if _is_cidr(t)]
            rows = self._conn.execute(
                "SELECT id, ip, hostname, label, status, misses FROM devices").fetchall()
            for r in rows:
                if r["id"] in seen_ids:
                    continue
                if targets and not _ip_in_any(r["ip"], targets):
                    continue
                misses = r["misses"] + 1
                status = r["status"]
                if status == "online" and misses >= offline_after:
                    status = "offline"
                    name = r["label"] or r["hostname"] or r["ip"]
                    ev = Event("device_offline", f"{name} ({r['ip']}) went offline",
                               {"ip": r["ip"], "misses": misses})
                    self._add_event(ev, scan_id, r["id"])
                    events.append(ev)
                self._conn.execute("UPDATE devices SET misses=?, status=? WHERE id=?",
                                   (misses, status, r["id"]))
            self._conn.commit()
        return events

    def record_port_scan(self, result: ScanResult, subnets: list[str],
                         scan_id: int | None = None, kind: str = "quick") -> list[Event]:
        """Apply a port scan: replace each scanned host's open-port set, log diffs."""
        seen_at = _iso(result.finished_at)
        events: list[Event] = []
        with self._lock:
            for host in result.hosts:
                if host.state != "up":
                    continue
                device_id, evs = self._upsert_host(host, scan_id, subnets, seen_at)
                events.extend(evs)
                device = self._conn.execute(
                    "SELECT label, hostname FROM devices WHERE id=?", (device_id,)).fetchone()
                label = device["label"] or device["hostname"] or host.ip
                if label != host.ip:
                    label = f"{label} ({host.ip})"

                old_rows = {
                    (r["port"], r["protocol"]): dict(r)
                    for r in self._conn.execute(
                        "SELECT * FROM ports WHERE device_id=?", (device_id,)).fetchall()
                }
                port_events = diff_ports(label, old_rows, host.ports)
                events.extend(port_events)
                for ev in port_events:
                    self._add_event(ev, scan_id, device_id)

                new_keys = set()
                for pr in host.ports:
                    if pr.state not in OPEN_STATES:
                        continue
                    new_keys.add(pr.key())
                    row = merge_port_rows(old_rows.get(pr.key()), pr)
                    first_seen = old_rows.get(pr.key(), {}).get("first_seen", seen_at)
                    self._conn.execute(
                        """INSERT INTO ports (device_id, port, protocol, state, service, product,
                           version, extrainfo, reason, confidence, first_seen, last_seen)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                           ON CONFLICT(device_id, port, protocol) DO UPDATE SET
                             state=excluded.state, service=excluded.service,
                             product=excluded.product, version=excluded.version,
                             extrainfo=excluded.extrainfo, reason=excluded.reason,
                             confidence=excluded.confidence, last_seen=excluded.last_seen""",
                        (device_id, row["port"], row["protocol"], row["state"], row["service"],
                         row["product"], row["version"], row["extrainfo"], row["reason"],
                         row["confidence"], first_seen, seen_at))
                for key in old_rows:
                    if key not in new_keys:
                        self._conn.execute(
                            "DELETE FROM ports WHERE device_id=? AND port=? AND protocol=?",
                            (device_id, key[0], key[1]))
                self._conn.execute(
                    "UPDATE devices SET last_port_scan=?, last_port_scan_kind=? WHERE id=?",
                    (seen_at, kind, device_id))
            self._conn.commit()
        return events

    def list_devices(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM devices").fetchall()
            counts = {
                r["device_id"]: r["n"] for r in self._conn.execute(
                    "SELECT device_id, COUNT(*) AS n FROM ports GROUP BY device_id").fetchall()
            }
        devices = [dict(r) for r in rows]
        for d in devices:
            d["open_port_count"] = counts.get(d["id"], 0)
            d["skip_ports"] = bool(d["skip_ports"])
        devices.sort(key=lambda d: _ip_sort_key(d["ip"]))
        return devices

    def get_device(self, device_id: int) -> dict | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            d["skip_ports"] = bool(d["skip_ports"])
            d["ports"] = [dict(r) for r in self._conn.execute(
                "SELECT * FROM ports WHERE device_id=? ORDER BY port, protocol",
                (device_id,)).fetchall()]
            d["open_port_count"] = len(d["ports"])
            d["events"] = [self._event_dict(r) for r in self._conn.execute(
                "SELECT * FROM events WHERE device_id=? ORDER BY id DESC LIMIT 50",
                (device_id,)).fetchall()]
        return d

    def update_device(self, device_id: int, fields: dict) -> dict | None:
        clean = {k: v for k, v in fields.items() if k in USER_EDITABLE}
        if "skip_ports" in clean:
            clean["skip_ports"] = 1 if clean["skip_ports"] else 0
        for key in ("label", "device_type", "notes"):
            if key in clean and isinstance(clean[key], str):
                clean[key] = clean[key].strip() or None
        if not clean:
            return self.get_device(device_id)
        sets = ", ".join(f"{k}=?" for k in clean)
        with self._lock:
            self._conn.execute(f"UPDATE devices SET {sets} WHERE id=?",
                               (*clean.values(), device_id))
            self._conn.commit()
        return self.get_device(device_id)

    def delete_device(self, device_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM devices WHERE id=?", (device_id,))
            self._conn.commit()
            return cur.rowcount > 0

    def all_ports(self) -> list[dict]:
        """Every known open port across the LAN, joined with its device."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT p.*, d.ip, d.hostname, d.label, d.status AS device_status
                   FROM ports p JOIN devices d ON d.id = p.device_id
                   ORDER BY p.port, p.protocol, d.ip""").fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- events
    @staticmethod
    def _event_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["details"] = json.loads(d["details"]) if d.get("details") else {}
        return d

    def list_events(self, limit: int = 200, since_id: int | None = None,
                    kinds: list[str] | None = None) -> list[dict]:
        sql = "SELECT * FROM events"
        clauses, params = [], []
        if since_id is not None:
            clauses.append("id > ?")
            params.append(since_id)
        if kinds:
            clauses.append(f"kind IN ({','.join('?' * len(kinds))})")
            params.extend(kinds)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._event_dict(r) for r in rows]

    # -------------------------------------------------------------------- map
    def map_data(self, gateway: str | None, local_ip: str | None) -> dict:
        """Nodes grouped by subnet with the gateway at the centre of each."""
        devices = self.list_devices()
        nodes, edges = [], []
        subnets: dict[str, list[dict]] = {}
        for d in devices:
            subnets.setdefault(d.get("subnet") or "unknown", []).append(d)

        for subnet, members in sorted(subnets.items()):
            hub_id = f"subnet:{subnet}"
            gw = next((m for m in members if m["ip"] == gateway), None)
            if gw:
                hub_id = f"device:{gw['id']}"
            else:
                nodes.append({"id": hub_id, "label": subnet, "kind": "subnet", "subnet": subnet})
            for m in members:
                nid = f"device:{m['id']}"
                nodes.append({
                    "id": nid,
                    "label": m.get("label") or m.get("hostname") or m["ip"],
                    "ip": m["ip"],
                    "kind": "gateway" if m["ip"] == gateway else
                            ("self" if m["ip"] == local_ip else (m.get("device_type") or "device")),
                    "status": m["status"],
                    "vendor": m.get("vendor"),
                    "open_port_count": m["open_port_count"],
                    "subnet": subnet,
                    "device_id": m["id"],
                })
                if nid != hub_id:
                    edges.append({"from": hub_id, "to": nid})
        # Link all subnet hubs together via the gateway if more than one subnet.
        hubs = [n["id"] for n in nodes if n["kind"] in ("subnet", "gateway")]
        if len(hubs) > 1:
            root = next((h for h in hubs if h.startswith("device:")), hubs[0])
            for h in hubs:
                if h != root:
                    edges.append({"from": root, "to": h, "dashes": True})
        return {"nodes": nodes, "edges": edges, "subnets": sorted(subnets)}

    def stats(self) -> dict:
        with self._lock:
            online = self._conn.execute(
                "SELECT COUNT(*) FROM devices WHERE status='online'").fetchone()[0]
            total = self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            ports = self._conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
            last = self._conn.execute(
                "SELECT finished_at FROM scans WHERE status='done' ORDER BY id DESC LIMIT 1"
            ).fetchone()
            events24 = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= datetime('now','-1 day')").fetchone()[0]
        return {"devices_online": online, "devices_total": total, "open_ports": ports,
                "last_scan": last[0] if last else None, "events_24h": events24}


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _ip_in_any(ip: str | None, nets: list) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def _ip_sort_key(ip: str | None):
    try:
        return (0, int(ipaddress.ip_address(ip or "0.0.0.0")))
    except ValueError:
        return (1, 0)
