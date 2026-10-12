from lanmap import localports
from lanmap.localports import (has_cap_sys_ptrace, in_host_pid_namespace, parse_cap_eff,
                               parse_ss_output, process_visibility_hint)

SS = """\
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*    users:(("avahi-daemon",pid=612,fd=12))
udp   UNCONN 0      0          127.0.0.1:53         0.0.0.0:*    users:(("dnsmasq",pid=800,fd=4))
tcp   LISTEN 0      4096         0.0.0.0:8096       0.0.0.0:*    users:(("jellyfin",pid=2410,fd=200),("jellyfin",pid=2410,fd=201))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=900,fd=3))
tcp   LISTEN 0      128             [::]:22            [::]:*    users:(("sshd",pid=900,fd=4))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*
tcp   LISTEN 0      4096               *:9100             *:*    users:(("node_exporter",pid=1234,fd=3))
tcp   ESTAB  0      0        192.168.1.5:22   192.168.1.9:51234 users:(("sshd",pid=4321,fd=4))
"""


def test_parse_ss_output():
    socks = parse_ss_output(SS)
    rows = [(s.protocol, s.local_addr, s.port, s.process, s.pid) for s in socks]
    assert ("tcp", "192.168.1.5", 22, "sshd", 4321) not in rows        # ESTAB ignored
    assert ("udp", "127.0.0.1", 53, "dnsmasq", 800) in rows
    assert ("udp", "0.0.0.0", 5353, "avahi-daemon", 612) in rows
    assert ("tcp", "0.0.0.0", 8096, "jellyfin", 2410) in rows
    assert ("tcp", "[::]", 22, "sshd", 900) in rows
    assert ("tcp", "127.0.0.1", 6379, None, None) in rows
    assert ("tcp", "*", 9100, "node_exporter", 1234) in rows
    assert [s.port for s in socks] == sorted(s.port for s in socks)

    d = {s.port: s.to_dict() for s in socks}
    assert d[8096]["exposed"] is True
    assert d[9100]["exposed"] is True
    assert d[6379]["exposed"] is False
    assert d[53]["exposed"] is False


def test_parse_ss_empty_and_garbage():
    assert parse_ss_output("") == []
    assert parse_ss_output("nonsense line\n\n") == []


DOCKER_DEFAULT_CAPS = "CapEff:\t00000000a80425fb\n"   # Docker's default bounding set
WITH_PTRACE = "CapEff:\t00000000a80c25fb\n"           # same + bit 19 (SYS_PTRACE)


def test_cap_parsing():
    assert parse_cap_eff("Name:\tpython\n" + DOCKER_DEFAULT_CAPS) == 0xa80425fb
    assert parse_cap_eff("no caps here") == 0
    assert parse_cap_eff("CapEff:\tzzz\n") == 0
    assert has_cap_sys_ptrace(DOCKER_DEFAULT_CAPS) is False
    assert has_cap_sys_ptrace(WITH_PTRACE) is True
    assert has_cap_sys_ptrace("CapEff:\t000001ffffffffff\n") is True   # full root


def test_host_pid_namespace_detection():
    assert in_host_pid_namespace("systemd") is True
    assert in_host_pid_namespace("init") is True
    assert in_host_pid_namespace("python") is False
    assert in_host_pid_namespace("sh") is False


def test_visibility_hint_names_what_is_missing(monkeypatch):
    monkeypatch.setattr(localports.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(localports, "in_host_pid_namespace", lambda pid1_comm=None: False)
    monkeypatch.setattr(localports, "has_cap_sys_ptrace", lambda status_text=None: False)
    hint = process_visibility_hint()
    assert "pid: host" in hint and "SYS_PTRACE" in hint and "root" not in hint

    monkeypatch.setattr(localports, "in_host_pid_namespace", lambda pid1_comm=None: True)
    monkeypatch.setattr(localports, "has_cap_sys_ptrace", lambda status_text=None: True)
    hint = process_visibility_hint()
    assert "AppArmor" in hint and "apparmor=unconfined" in hint

    monkeypatch.setattr(localports.os, "geteuid", lambda: 1000, raising=False)
    assert "not running as root" in process_visibility_hint()
