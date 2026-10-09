"""Listening sockets on the machine running lanmap, mapped to processes.

This is the one place we can answer "what is *using* this port" rather than
"what service is nmap guessing". Needs host networking + host PID namespace
(and root) inside Docker to see the host's sockets and process names.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field


@dataclass
class ListeningSocket:
    protocol: str          # tcp / udp
    local_addr: str        # 0.0.0.0, 127.0.0.1, [::], 192.168.1.5 ...
    port: int
    process: str | None = None
    pid: int | None = None
    user_hint: str | None = None

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "local_addr": self.local_addr,
            "port": self.port,
            "process": self.process,
            "pid": self.pid,
            "exposed": self.local_addr in ("0.0.0.0", "*", "[::]", "::") or
                       not self.local_addr.startswith(("127.", "[::1]", "::1")),
        }


_USERS_RE = re.compile(r'users:\(\((.*)\)\)')
_PROC_RE = re.compile(r'"([^"]*)",pid=(\d+)')


def _split_addr(addr: str) -> tuple[str, int | None]:
    """'0.0.0.0:8080' -> ('0.0.0.0', 8080); '[::]:22' -> ('[::]', 22); '*:53' -> ('*', 53)."""
    if ":" not in addr:
        return addr, None
    host, _, port = addr.rpartition(":")
    try:
        return host or "*", int(port)
    except ValueError:
        return addr, None


def parse_ss_output(text: str) -> list[ListeningSocket]:
    """Parse `ss -H -lptun` output (no header, listening, processes, tcp+udp, numeric)."""
    sockets: list[ListeningSocket] = []
    seen: set[tuple[str, str, int]] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 6)
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        state = parts[1]
        if proto not in ("tcp", "udp"):
            continue
        if proto == "tcp" and state.upper() != "LISTEN":
            continue
        local = parts[4]
        host, port = _split_addr(local)
        if port is None:
            continue
        process = pid = None
        tail = parts[6] if len(parts) > 6 else ""
        m = _USERS_RE.search(tail)
        if m:
            pm = _PROC_RE.search(m.group(1))
            if pm:
                process, pid = pm.group(1), int(pm.group(2))
        key = (proto, host, port)
        if key in seen:
            continue
        seen.add(key)
        sockets.append(ListeningSocket(protocol=proto, local_addr=host, port=port,
                                       process=process, pid=pid))
    sockets.sort(key=lambda s: (s.port, s.protocol, s.local_addr))
    return sockets


def list_listening_sockets() -> tuple[list[ListeningSocket], str | None]:
    """Return (sockets, error). error is set when ss is unavailable."""
    try:
        proc = subprocess.run(["ss", "-H", "-lptun"], capture_output=True, text=True,
                              timeout=10, check=False)
    except FileNotFoundError:
        return [], "ss (iproute2) is not installed"
    except subprocess.SubprocessError as exc:
        return [], f"ss failed: {exc}"
    if proc.returncode != 0 and not proc.stdout.strip():
        return [], f"ss exited {proc.returncode}: {proc.stderr.strip()[:200]}"
    return parse_ss_output(proc.stdout), None
