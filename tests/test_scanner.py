from lanmap import scanner
from lanmap.config import Settings

from conftest import host, nmaprun


def test_parse_discovery_basic():
    xml = nmaprun(
        host("192.168.1.1", "aa:bb:cc:00:00:01", "Ubiquiti", "gw"),
        host("192.168.1.7", "aa:bb:cc:00:00:07"),
        host("192.168.1.8", state="down"),
    )
    r = scanner.parse_nmap_xml(xml, "discovery")
    assert r.kind == "discovery"
    assert r.nmap_version == "7.94"
    assert len(r.hosts) == 3
    assert len(r.hosts_up) == 2
    gw = r.hosts[0]
    assert gw.mac == "AA:BB:CC:00:00:01"      # normalised to upper-case
    assert gw.vendor == "Ubiquiti"
    assert gw.hostname == "gw"
    assert gw.latency_ms == 1.5
    assert r.hosts[1].vendor is None
    assert r.finished_at.timestamp() == 1700000060


def test_parse_ports_and_os():
    xml = nmaprun(host("192.168.1.20", "aa:bb:cc:00:00:20", "Raspberry Pi", "pi", ports=[
        (22, "tcp", "open", "ssh", "OpenSSH", "9.2p1", "Debian"),
        (80, "tcp", "closed", "http"),
        (8096, "tcp", "open", "http", "Jellyfin"),
        (53, "udp", "open|filtered", "domain"),
    ], os_name="Linux 5.10"))
    r = scanner.parse_nmap_xml(xml, "ports")
    h = r.hosts[0]
    assert h.ports_scanned
    assert h.os_guess == "Linux 5.10" and h.os_accuracy == 94
    assert h.extraports == {"closed": 990}
    assert [p.port for p in h.open_ports] == [22, 8096, 53]
    ssh = h.ports[0]
    assert ssh.summary() == "OpenSSH 9.2p1 (Debian)"
    assert ssh.confidence == 10
    assert h.ports[1].state == "closed"
    assert h.ports[2].summary() == "Jellyfin"
    assert h.ports[3].summary() == "domain"


def test_parse_truncated_xml_is_salvaged():
    xml = nmaprun(host("10.0.0.5", "aa:bb:cc:dd:ee:ff"))
    cut = xml[: xml.index("<runstats")]
    r = scanner.parse_nmap_xml(cut)
    assert r.hosts[0].ip == "10.0.0.5"
    assert r.summary is None


def test_host_without_ip_is_skipped():
    xml = '<nmaprun start="1"><host><status state="up"/></host></nmaprun>'
    assert scanner.parse_nmap_xml(xml).hosts == []


def test_discovery_cmd(monkeypatch):
    s = Settings(subnets=["192.168.1.0/24"], interface="eth0")
    monkeypatch.setattr(scanner, "is_root", lambda: True)
    cmd = scanner.build_discovery_cmd(s, s.subnets)
    assert cmd[0] == "nmap" and "-sn" in cmd and "-PR" in cmd
    assert cmd[cmd.index("-e") + 1] == "eth0"
    assert cmd[-1] == "192.168.1.0/24"

    monkeypatch.setattr(scanner, "is_root", lambda: False)
    cmd = scanner.build_discovery_cmd(s, s.subnets)
    assert "-PR" not in cmd and "-PE" in cmd


def test_port_scan_cmd_quick_vs_deep(monkeypatch):
    s = Settings(subnets=["192.168.1.0/24"], max_parallel_hosts=2, host_timeout_seconds=120)
    monkeypatch.setattr(scanner, "is_root", lambda: True)
    quick = scanner.build_port_scan_cmd(s, ["192.168.1.5"], deep=False)
    assert "-sS" in quick and "--top-ports" in quick and quick[quick.index("--top-ports") + 1] == "1000"
    assert "--version-light" in quick and "-O" not in quick
    assert quick[quick.index("--host-timeout") + 1] == "120s"
    assert quick[quick.index("--max-hostgroup") + 1] == "2"

    deep = scanner.build_port_scan_cmd(s, ["192.168.1.5"], deep=True)
    assert "-p" in deep and deep[deep.index("-p") + 1] == "1-65535"
    assert "-O" in deep and "--version-light" not in deep

    custom = scanner.build_port_scan_cmd(s, ["192.168.1.5"], ports="22,80,443")
    assert custom[custom.index("-p") + 1] == "22,80,443"

    monkeypatch.setattr(scanner, "is_root", lambda: False)
    unpriv = scanner.build_port_scan_cmd(s, ["192.168.1.5"], deep=True)
    assert "-sT" in unpriv and "-O" not in unpriv


def test_port_spec_variants():
    assert scanner._port_spec_args("top100") == ["--top-ports", "100"]
    assert scanner._port_spec_args("top") == ["--top-ports", "1000"]
    assert scanner._port_spec_args("all") == ["-p-"]
    assert scanner._port_spec_args("1-1024,8080") == ["-p", "1-1024,8080"]


def test_run_nmap_missing_binary():
    import pytest
    with pytest.raises(scanner.NmapError):
        scanner.run_nmap(["/definitely/not/nmap", "-sn", "127.0.0.1"], timeout=5)
