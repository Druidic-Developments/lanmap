"""Listening sockets on the machine running lanmap, mapped to processes.

This is the one place we can answer "what is *using* this port" rather than
"what service is nmap guessing". Needs host networking + host PID namespace
(and root) inside Docker to see the host's sockets and process names.
"""

from __future__ import annotations

import os
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


# --------------------------------------------------------------------------- #
# Why can't we see process names?  `ss -p` reads /proc/<pid>/fd for every
# process, which needs: root, the host's PID namespace (pid: host), and
# CAP_SYS_PTRACE (not in Docker's default capability set).  AppArmor's
# docker-default profile can also block it on some distros.
# --------------------------------------------------------------------------- #

CAP_SYS_PTRACE_BIT = 19


def parse_cap_eff(status_text: str) -> int:
    """Effective capability mask from /proc/self/status text."""
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            try:
                return int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return 0
    return 0


def has_cap_sys_ptrace(status_text: str | None = None) -> bool:
    if status_text is None:
        try:
            with open("/proc/self/status", encoding="utf-8") as fh:
                status_text = fh.read()
        except OSError:
            return False
    return bool(parse_cap_eff(status_text) & (1 << CAP_SYS_PTRACE_BIT))


def in_host_pid_namespace(pid1_comm: str | None = None) -> bool:
    """True when PID 1 looks like the host's init, not this container's entrypoint."""
    if pid1_comm is None:
        try:
            with open("/proc/1/comm", encoding="utf-8") as fh:
                pid1_comm = fh.read().strip()
        except OSError:
            return False
    return pid1_comm.lower() in {"systemd", "init", "launchd", "openrc-init", "runit", "s6-svscan"}


def process_visibility_hint() -> str | None:
    """Explain why process names are missing, or None if everything needed is present."""
    missing: list[str] = []
    try:
        if os.geteuid() != 0:
            missing.append("not running as root")
    except AttributeError:
        pass
    if not in_host_pid_namespace():
        missing.append("not in the host PID namespace — add `pid: host` to the compose service")
    if not has_cap_sys_ptrace():
        missing.append("missing CAP_SYS_PTRACE — add `SYS_PTRACE` under cap_add")
    if missing:
        return "Process names unavailable: " + "; ".join(missing) + "."
    return ("Process names unavailable even though root, host PID namespace and CAP_SYS_PTRACE "
            "are all present — AppArmor is probably blocking /proc access. Add "
            "`security_opt: [\"apparmor=unconfined\"]` to the compose service.")


def list_listening_sockets() -> tuple[list[ListeningSocket], str | None, str | None]:
    """Return (sockets, error, hint).

    error: ss itself failed.
    hint:  ss worked but couldn't attribute sockets to processes, with the reason.
    """
    try:
        proc = subprocess.run(["ss", "-H", "-lptun"], capture_output=True, text=True,
                              timeout=10, check=False)
    except FileNotFoundError:
        return [], "ss (iproute2) is not installed", None
    except subprocess.SubprocessError as exc:
        return [], f"ss failed: {exc}", None
    if proc.returncode != 0 and not proc.stdout.strip():
        return [], f"ss exited {proc.returncode}: {proc.stderr.strip()[:200]}", None
    sockets = parse_ss_output(proc.stdout)
    hint = None
    if sockets and not any(s.process for s in sockets):
        hint = process_visibility_hint()
    return sockets, None, hint
