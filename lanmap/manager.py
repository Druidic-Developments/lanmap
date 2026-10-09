"""Background scan runner + scheduler.

One worker thread drains a job queue so nmap runs never overlap. The scheduler
thread enqueues a discovery sweep every `scan_interval_minutes` and a quick
port scan of online hosts every `port_scan_interval_minutes`.

`runner` is injectable so tests can feed canned XML instead of running nmap.
"""

from __future__ import annotations

import logging
import queue
import shlex
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import scanner
from .config import Settings
from .db import Store

log = logging.getLogger("lanmap.manager")

Runner = Callable[[list[str], int | None], str]


@dataclass
class Job:
    kind: str                       # discovery / ports
    targets: list[str]
    deep: bool = False
    ports: str | None = None
    label: str = ""
    requested_by: str = "scheduler"
    id: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "targets": self.targets, "deep": self.deep,
                "ports": self.ports, "label": self.label, "requested_by": self.requested_by,
                "created_at": self.created_at.isoformat(timespec="seconds")}


class ScanManager:
    def __init__(self, settings: Settings, store: Store, runner: Runner | None = None):
        self.settings = settings
        self.store = store
        self.runner = runner or scanner.run_nmap
        self._queue: queue.Queue[Job] = queue.Queue()
        self._pending: list[Job] = []
        self._current: Job | None = None
        self._current_scan_id: int | None = None
        self._current_started: float | None = None
        self._last_error: str | None = None
        self._next_id = 1
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._scheduler: threading.Thread | None = None
        self._last_discovery = 0.0
        self._last_port_scan = 0.0
        self.nmap_version = scanner.nmap_version(settings.nmap_path)
        self.is_root = scanner.is_root()

    # ----------------------------------------------------------------- control
    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._work_loop, name="lanmap-worker", daemon=True)
        self._worker.start()
        self._scheduler = threading.Thread(target=self._schedule_loop, name="lanmap-sched",
                                           daemon=True)
        self._scheduler.start()

    def stop(self) -> None:
        self._stop.set()

    def enqueue(self, job: Job) -> Job:
        with self._lock:
            job.id = self._next_id
            self._next_id += 1
            # Collapse duplicate scheduler discovery jobs.
            for p in self._pending:
                if p.kind == job.kind and p.targets == job.targets and p.deep == job.deep:
                    return p
            self._pending.append(job)
        self._queue.put(job)
        return job

    def enqueue_discovery(self, requested_by: str = "user") -> Job | None:
        if not self.settings.subnets:
            self._last_error = "No subnet configured and none could be autodetected"
            return None
        return self.enqueue(Job("discovery", list(self.settings.subnets),
                                label="Discovery sweep", requested_by=requested_by))

    def enqueue_port_scan(self, targets: list[str], deep: bool = False,
                          ports: str | None = None, requested_by: str = "user") -> Job | None:
        skip = set(self.settings.skip_hosts)
        targets = [t for t in targets if t not in skip]
        if not targets:
            return None
        label = ("Deep" if deep else "Quick") + f" port scan of {len(targets)} host(s)"
        return self.enqueue(Job("ports", targets, deep=deep, ports=ports, label=label,
                                requested_by=requested_by))

    def enqueue_port_scan_all_online(self, deep: bool = False,
                                     requested_by: str = "scheduler") -> Job | None:
        ips = [d["ip"] for d in self.store.list_devices()
               if d["status"] == "online" and not d["skip_ports"] and d["ip"]]
        return self.enqueue_port_scan(ips, deep=deep, requested_by=requested_by)

    def status(self) -> dict:
        with self._lock:
            current = self._current.to_dict() if self._current else None
            pending = [j.to_dict() for j in self._pending]
            elapsed = round(time.time() - self._current_started, 1) if self._current_started else None
        return {
            "running": current is not None,
            "current": current,
            "current_scan_id": self._current_scan_id,
            "elapsed_seconds": elapsed,
            "queue": pending,
            "last_error": self._last_error,
            "nmap_version": self.nmap_version,
            "is_root": self.is_root,
            "next_discovery_in_seconds": self._seconds_until(self._last_discovery,
                                                             self.settings.scan_interval_minutes),
            "next_port_scan_in_seconds": self._seconds_until(
                self._last_port_scan, self.settings.port_scan_interval_minutes),
        }

    @staticmethod
    def _seconds_until(last: float, interval_minutes: int) -> int | None:
        if interval_minutes <= 0:
            return None
        return max(0, int(last + interval_minutes * 60 - time.time()))

    # ------------------------------------------------------------------- loops
    def _schedule_loop(self) -> None:
        # Kick off an immediate discovery on boot.
        if self.settings.scan_interval_minutes > 0:
            self.enqueue_discovery(requested_by="scheduler")
        while not self._stop.wait(15):
            now = time.time()
            si = self.settings.scan_interval_minutes
            if si > 0 and now - self._last_discovery >= si * 60:
                self.enqueue_discovery(requested_by="scheduler")
                self._last_discovery = now
            pi = self.settings.port_scan_interval_minutes
            if pi > 0 and now - self._last_port_scan >= pi * 60:
                self.enqueue_port_scan_all_online(requested_by="scheduler")
                self._last_port_scan = now

    def _work_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            with self._lock:
                if job in self._pending:
                    self._pending.remove(job)
                self._current = job
                self._current_started = time.time()
            try:
                self.run_job(job)
            except Exception as exc:  # noqa: BLE001 - keep the worker alive
                log.exception("job %s failed", job.id)
                self._last_error = str(exc)
            finally:
                with self._lock:
                    self._current = None
                    self._current_scan_id = None
                    self._current_started = None
                self._queue.task_done()

    # ----------------------------------------------------------------- running
    def run_job(self, job: Job) -> dict:
        """Execute a job synchronously (the worker calls this; tests can too)."""
        if job.kind == "discovery":
            cmd = scanner.build_discovery_cmd(self.settings, job.targets)
            timeout = 600
        else:
            cmd = scanner.build_port_scan_cmd(self.settings, job.targets, deep=job.deep,
                                              ports=job.ports)
            per_host = self.settings.host_timeout_seconds
            timeout = max(300, per_host * max(1, len(job.targets)) // max(
                1, self.settings.max_parallel_hosts) + 120)
        args = shlex.join(cmd)
        scan_id = self.store.start_scan(job.kind, job.targets, args)
        self._current_scan_id = scan_id
        log.info("scan %s: %s", scan_id, args)
        try:
            xml = self.runner(cmd, timeout)
            result = scanner.parse_nmap_xml(xml, kind=job.kind)
            result.targets = list(job.targets)
            if job.kind == "discovery":
                events = self.store.record_discovery(
                    result, self.settings.subnets, scan_id,
                    offline_after=self.settings.offline_after_misses)
                self._last_discovery = time.time()
            else:
                events = self.store.record_port_scan(
                    result, self.settings.subnets, scan_id,
                    kind="deep" if job.deep else "quick")
                if job.requested_by == "scheduler":
                    self._last_port_scan = time.time()
            self.store.finish_scan(scan_id, "done", hosts_up=len(result.hosts_up),
                                   summary=result.summary, event_count=len(events))
            self._last_error = None
            self._current_scan_id = None
            return {"scan_id": scan_id, "hosts_up": len(result.hosts_up),
                    "events": [e.to_dict() for e in events]}
        except scanner.NmapError as exc:
            self.store.finish_scan(scan_id, "failed", error=str(exc))
            self._last_error = str(exc)
            raise
        except Exception as exc:
            self.store.finish_scan(scan_id, "failed", error=f"{type(exc).__name__}: {exc}")
            raise
