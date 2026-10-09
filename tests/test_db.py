from lanmap import scanner
from lanmap.db import identity_for, subnet_for
from lanmap.scanner import HostResult

from conftest import host, nmaprun

SUBNETS = ["192.168.1.0/24"]


def _disc(*hosts, **kw):
    r = scanner.parse_nmap_xml(nmaprun(*hosts, **kw), "discovery")
    r.targets = SUBNETS
    return r


def _ports(*hosts, **kw):
    r = scanner.parse_nmap_xml(nmaprun(*hosts, **kw), "ports")
    r.targets = [h.ip for h in r.hosts]
    return r


def test_identity_and_subnet_helpers():
    assert identity_for(HostResult(ip="1.2.3.4", state="up", mac="AA:BB")) == "AA:BB"
    assert identity_for(HostResult(ip="1.2.3.4", state="up")) == "ip:1.2.3.4"
    assert subnet_for("192.168.1.9", SUBNETS) == "192.168.1.0/24"
    assert subnet_for("10.9.8.7", SUBNETS) == "10.9.8.0/24"
    assert subnet_for("garbage", SUBNETS) is None


def test_discovery_creates_devices_and_events(store):
    sid = store.start_scan("discovery", SUBNETS)
    evs = store.record_discovery(_disc(
        host("192.168.1.1", "aa:bb:cc:00:00:01", "Ubiquiti", "gw"),
        host("192.168.1.5", "aa:bb:cc:00:00:05", "MSI"),
    ), SUBNETS, scan_id=sid)
    store.finish_scan(sid, "done", hosts_up=2, event_count=len(evs))

    assert [e.kind for e in evs] == ["device_new", "device_new"]
    devices = store.list_devices()
    assert [d["ip"] for d in devices] == ["192.168.1.1", "192.168.1.5"]
    assert devices[0]["hostname"] == "gw" and devices[0]["subnet"] == "192.168.1.0/24"
    assert devices[0]["status"] == "online" and devices[0]["open_port_count"] == 0
    scans = store.list_scans()
    assert scans[0]["status"] == "done" and scans[0]["event_count"] == 2
    assert store.list_events()[0]["scan_id"] == sid


def test_offline_after_misses_and_back_online(store):
    a = host("192.168.1.1", "aa:bb:cc:00:00:01")
    b = host("192.168.1.5", "aa:bb:cc:00:00:05", hostname="pi")
    store.record_discovery(_disc(a, b), SUBNETS)
    store.record_discovery(_disc(a), SUBNETS, offline_after=2)        # miss 1
    assert store.list_devices()[1]["status"] == "online"
    evs = store.record_discovery(_disc(a), SUBNETS, offline_after=2)  # miss 2 -> offline
    assert [e.kind for e in evs] == ["device_offline"]
    d = store.list_devices()[1]
    assert d["status"] == "offline" and d["misses"] == 2
    evs = store.record_discovery(_disc(a, b), SUBNETS)
    assert [e.kind for e in evs] == ["device_online"]
    d = store.list_devices()[1]
    assert d["status"] == "online" and d["misses"] == 0


def test_devices_outside_swept_targets_are_not_aged(store):
    far = host("10.0.0.9", "aa:bb:cc:00:00:09")
    store.record_discovery(_disc(far), SUBNETS)
    r = _disc(host("192.168.1.1", "aa:bb:cc:00:00:01"))
    r.targets = ["192.168.1.0/24"]
    for _ in range(3):
        store.record_discovery(r, SUBNETS)
    assert store.list_devices()[0]["misses"] == 0


def test_ip_change_keeps_same_device(store):
    store.record_discovery(_disc(host("192.168.1.5", "aa:bb:cc:00:00:05")), SUBNETS)
    evs = store.record_discovery(_disc(host("192.168.1.77", "aa:bb:cc:00:00:05")), SUBNETS)
    assert [e.kind for e in evs] == ["ip_changed"]
    devices = store.list_devices()
    assert len(devices) == 1 and devices[0]["ip"] == "192.168.1.77"


def test_port_scan_records_diffs_and_replaces_set(store):
    store.record_discovery(_disc(host("192.168.1.20", "aa:bb:cc:00:00:20", hostname="pi")), SUBNETS)
    evs = store.record_port_scan(_ports(host("192.168.1.20", "aa:bb:cc:00:00:20", ports=[
        (22, "tcp", "open", "ssh", "OpenSSH", "9.2"),
        (80, "tcp", "open", "http", "nginx"),
        (443, "tcp", "closed", "https"),
    ], os_name="Linux 5.10")), SUBNETS, kind="quick")
    assert sorted(e.kind for e in evs) == ["port_opened", "port_opened"]
    d = store.get_device(1)
    assert [p["port"] for p in d["ports"]] == [22, 80]
    assert d["os_guess"] == "Linux 5.10" and d["last_port_scan_kind"] == "quick"
    first_seen_22 = d["ports"][0]["first_seen"]

    evs = store.record_port_scan(_ports(host("192.168.1.20", "aa:bb:cc:00:00:20", ports=[
        (22, "tcp", "open", "ssh", "OpenSSH", "9.6"),
        (8096, "tcp", "open", "http", "Jellyfin"),
    ]), end=1700009999), SUBNETS, kind="deep")
    kinds = sorted(e.kind for e in evs)
    assert kinds == ["port_closed", "port_opened", "service_changed"]
    d = store.get_device(1)
    assert [p["port"] for p in d["ports"]] == [22, 8096]
    assert d["ports"][0]["version"] == "9.6"
    assert d["ports"][0]["first_seen"] == first_seen_22          # preserved across rescans
    assert d["last_port_scan_kind"] == "deep"
    assert store.stats()["open_ports"] == 2
    allp = store.all_ports()
    assert [(p["port"], p["ip"]) for p in allp] == [(22, "192.168.1.20"), (8096, "192.168.1.20")]


def test_port_scan_without_mac_matches_by_ip(store):
    store.record_discovery(_disc(host("192.168.1.30", "aa:bb:cc:00:00:30", hostname="nas")), SUBNETS)
    store.record_port_scan(_ports(host("192.168.1.30", ports=[(445, "tcp", "open", "microsoft-ds")])),
                           SUBNETS)
    devices = store.list_devices()
    assert len(devices) == 1 and devices[0]["open_port_count"] == 1
    assert devices[0]["mac"] == "AA:BB:CC:00:00:30"


def test_device_first_seen_by_ip_then_gains_mac(store):
    store.record_port_scan(_ports(host("192.168.1.40", ports=[(22, "tcp", "open", "ssh")])), SUBNETS)
    assert store.list_devices()[0]["identity"] == "ip:192.168.1.40"
    store.record_discovery(_disc(host("192.168.1.40", "aa:bb:cc:00:00:40")), SUBNETS)
    devices = store.list_devices()
    assert len(devices) == 1
    assert devices[0]["identity"] == "AA:BB:CC:00:00:40" and devices[0]["open_port_count"] == 1


def test_update_device_user_fields_only(store):
    store.record_discovery(_disc(host("192.168.1.5", "aa:bb:cc:00:00:05")), SUBNETS)
    d = store.update_device(1, {"label": "  Main PC ", "device_type": "desktop", "notes": "x",
                                "skip_ports": True, "ip": "9.9.9.9", "status": "offline"})
    assert d["label"] == "Main PC" and d["device_type"] == "desktop" and d["skip_ports"] is True
    assert d["ip"] == "192.168.1.5" and d["status"] == "online"      # not user-editable
    d = store.update_device(1, {"label": "   "})
    assert d["label"] is None
    assert store.update_device(999, {"label": "x"}) is None


def test_delete_device_cascades(store):
    store.record_discovery(_disc(host("192.168.1.5", "aa:bb:cc:00:00:05")), SUBNETS)
    store.record_port_scan(_ports(host("192.168.1.5", "aa:bb:cc:00:00:05",
                                       ports=[(22, "tcp", "open", "ssh")])), SUBNETS)
    assert store.delete_device(1) is True
    assert store.list_devices() == [] and store.all_ports() == []
    assert store.delete_device(1) is False
    assert all(e["device_id"] is None for e in store.list_events())


def test_events_filter_and_since(store):
    store.record_discovery(_disc(host("192.168.1.1", "aa:bb:cc:00:00:01"),
                                 host("192.168.1.2", "aa:bb:cc:00:00:02")), SUBNETS)
    store.record_discovery(_disc(host("192.168.1.1", "aa:bb:cc:00:00:01")), SUBNETS, offline_after=1)
    assert [e["kind"] for e in store.list_events()] == ["device_offline", "device_new", "device_new"]
    assert [e["kind"] for e in store.list_events(kinds=["device_new"])] == ["device_new", "device_new"]
    assert [e["id"] for e in store.list_events(since_id=2)] == [3]
    assert len(store.list_events(limit=1)) == 1


def test_map_data_groups_by_subnet_with_gateway_hub(store):
    store.record_discovery(_disc(
        host("192.168.1.1", "aa:bb:cc:00:00:01", hostname="gw"),
        host("192.168.1.5", "aa:bb:cc:00:00:05"),
        host("10.0.0.3", "aa:bb:cc:00:00:03"),
    ), SUBNETS)
    m = store.map_data(gateway="192.168.1.1", local_ip="192.168.1.5")
    kinds = {n["id"]: n["kind"] for n in m["nodes"]}
    assert kinds["device:1"] == "gateway" and kinds["device:2"] == "self"
    assert kinds["subnet:10.0.0.0/24"] == "subnet"
    assert {"from": "device:1", "to": "device:2"} in m["edges"]
    assert {"from": "subnet:10.0.0.0/24", "to": "device:3"} in m["edges"]
    assert {"from": "device:1", "to": "subnet:10.0.0.0/24", "dashes": True} in m["edges"]
    assert m["subnets"] == ["10.0.0.0/24", "192.168.1.0/24"]

    m2 = store.map_data(gateway=None, local_ip=None)
    assert any(n["id"] == "subnet:192.168.1.0/24" for n in m2["nodes"])
