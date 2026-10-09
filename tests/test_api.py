import time

import pytest
from fastapi.testclient import TestClient

from lanmap import scanner
from lanmap.app import create_app
from lanmap.manager import Job, ScanManager

from conftest import host, nmaprun

DISCOVERY = nmaprun(
    host("192.168.1.1", "aa:bb:cc:00:00:01", "Ubiquiti", "gw"),
    host("192.168.1.20", "aa:bb:cc:00:00:20", "Raspberry Pi", "pi"),
    host("192.168.1.99", "aa:bb:cc:00:00:99", "Tuya"),
)
PORTS = nmaprun(host("192.168.1.20", "aa:bb:cc:00:00:20", ports=[
    (22, "tcp", "open", "ssh", "OpenSSH", "9.2p1", "Debian"),
    (3001, "tcp", "open", "http", "Uptime Kuma"),
]), args="nmap -sS")


class FakeNmap:
    def __init__(self):
        self.calls = []
        self.fail_next = False

    def __call__(self, cmd, timeout):
        self.calls.append(cmd)
        if self.fail_next:
            self.fail_next = False
            raise scanner.NmapError("boom")
        return DISCOVERY if "-sn" in cmd else PORTS


@pytest.fixture
def env(settings, store):
    fake = FakeNmap()
    mgr = ScanManager(settings, store, runner=fake)
    app = create_app(settings, store, mgr, start_workers=False)
    with TestClient(app) as client:
        yield client, mgr, fake, store


def test_status_and_empty_state(env):
    client, mgr, fake, store = env
    r = client.get("/api/status").json()
    assert r["settings"]["subnets"] == ["192.168.1.0/24"]
    assert r["scanner"]["running"] is False
    assert r["stats"]["devices_total"] == 0
    assert client.get("/api/devices").json() == []
    assert client.get("/api/map").json()["nodes"] == []
    assert client.get("/").status_code == 200
    assert "lanmap" in client.get("/").text


def test_discovery_then_port_scan_flow(env):
    client, mgr, fake, store = env
    out = mgr.run_job(Job("discovery", ["192.168.1.0/24"]))
    assert out["hosts_up"] == 3 and len(out["events"]) == 3
    devices = client.get("/api/devices").json()
    assert [d["ip"] for d in devices] == ["192.168.1.1", "192.168.1.20", "192.168.1.99"]
    assert devices[0]["vendor"] == "Ubiquiti"

    out = mgr.run_job(Job("ports", ["192.168.1.20"]))
    d = client.get("/api/devices/2").json()
    assert [p["port"] for p in d["ports"]] == [22, 3001]
    assert d["ports"][0]["product"] == "OpenSSH"
    assert any(e["kind"] == "port_opened" for e in d["events"])

    ports = client.get("/api/ports").json()
    assert [(p["port"], p["ip"]) for p in ports] == [(22, "192.168.1.20"), (3001, "192.168.1.20")]
    events = client.get("/api/events?kinds=port_opened").json()
    assert len(events) == 2
    scans = client.get("/api/scans").json()
    assert [s["kind"] for s in scans] == ["ports", "discovery"]
    assert scans[0]["status"] == "done"
    st = client.get("/api/status").json()
    assert st["stats"] == {**st["stats"], "devices_online": 3, "open_ports": 2}
    assert st["scanner"]["current_scan_id"] is None


def test_patch_and_delete_device(env):
    client, mgr, fake, store = env
    mgr.run_job(Job("discovery", ["192.168.1.0/24"]))
    r = client.patch("/api/devices/2", json={"label": "Media Pi", "device_type": "server",
                                             "notes": "runs jellyfin", "skip_ports": True})
    assert r.status_code == 200
    d = r.json()
    assert d["label"] == "Media Pi" and d["device_type"] == "server" and d["skip_ports"] is True
    # Partial patch leaves other fields alone.
    d = client.patch("/api/devices/2", json={"notes": "x"}).json()
    assert d["label"] == "Media Pi" and d["notes"] == "x"
    assert client.patch("/api/devices/404", json={"label": "x"}).status_code == 404
    assert client.get("/api/devices/404").status_code == 404
    assert client.delete("/api/devices/2").status_code == 200
    assert client.delete("/api/devices/2").status_code == 404
    assert len(client.get("/api/devices").json()) == 2


def test_scan_queueing_rules(env):
    client, mgr, fake, store = env
    mgr.run_job(Job("discovery", ["192.168.1.0/24"]))
    client.patch("/api/devices/2", json={"skip_ports": True})

    r = client.post("/api/scan/discovery")
    assert r.status_code == 200 and r.json()["queued"]["kind"] == "discovery"
    # Duplicate discovery collapses into the pending one.
    r2 = client.post("/api/scan/discovery")
    assert r2.json()["queued"]["id"] == r.json()["queued"]["id"]
    assert len(client.get("/api/status").json()["scanner"]["queue"]) == 1

    # Device 2 is skip-flagged -> nothing scannable.
    assert client.post("/api/scan/ports", json={"device_ids": [2]}).status_code == 400
    # 192.168.1.99 is in LANMAP_SKIP_HOSTS -> nothing scannable.
    assert client.post("/api/scan/ports", json={"ips": ["192.168.1.99"]}).status_code == 400
    # Gateway is fine; custom port spec is carried through.
    r = client.post("/api/scan/ports", json={"device_ids": [1], "ports": "1-1024", "deep": True})
    q = r.json()["queued"]
    assert q["targets"] == ["192.168.1.1"] and q["ports"] == "1-1024" and q["deep"] is True
    # all_online excludes the skip-flagged device and the skip-host.
    r = client.post("/api/scan/ports", json={"all_online": True})
    assert r.json()["queued"]["targets"] == ["192.168.1.1"]
    assert client.post("/api/scan/ports", json={}).status_code == 400


def test_failed_scan_is_recorded(env):
    client, mgr, fake, store = env
    fake.fail_next = True
    with pytest.raises(scanner.NmapError):
        mgr.run_job(Job("discovery", ["192.168.1.0/24"]))
    s = client.get("/api/scans").json()[0]
    assert s["status"] == "failed" and s["error"] == "boom"
    assert client.get("/api/status").json()["scanner"]["last_error"] == "boom"


def test_worker_thread_runs_queued_jobs(env):
    client, mgr, fake, store = env
    mgr.start()
    try:
        client.post("/api/scan/discovery")
        deadline = time.time() + 5
        while time.time() < deadline and not client.get("/api/devices").json():
            time.sleep(0.05)
        assert len(client.get("/api/devices").json()) == 3
        assert client.get("/api/status").json()["scanner"]["running"] is False
    finally:
        mgr.stop()


def test_localports_endpoint_shape(env):
    client, *_ = env
    r = client.get("/api/localports").json()
    assert "sockets" in r and "error" in r
    for s in r["sockets"]:
        assert {"port", "protocol", "local_addr", "exposed"} <= set(s)
