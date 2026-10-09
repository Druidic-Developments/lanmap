from lanmap.differ import diff_device, diff_ports, merge_port_rows
from lanmap.scanner import HostResult, PortResult


def _h(ip="192.168.1.5", mac="AA:BB:CC:00:00:05", hostname=None, vendor=None):
    return HostResult(ip=ip, state="up", mac=mac, hostname=hostname, vendor=vendor)


def test_new_device_event():
    evs = diff_device(None, _h(vendor="Apple"))
    assert [e.kind for e in evs] == ["device_new"]
    assert "Apple" in evs[0].message
    assert evs[0].severity == "notice"


def test_no_events_when_nothing_changed():
    dev = {"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05", "hostname": "x", "status": "online"}
    assert diff_device(dev, _h(hostname="x")) == []


def test_ip_hostname_mac_and_online_events():
    dev = {"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05", "hostname": "old", "status": "offline",
           "label": "Pi"}
    evs = diff_device(dev, _h(ip="192.168.1.9", mac="AA:BB:CC:00:00:06", hostname="new"))
    kinds = [e.kind for e in evs]
    assert kinds == ["device_online", "ip_changed", "hostname_changed", "mac_changed"]
    assert "192.168.1.5" in evs[1].message and "192.168.1.9" in evs[1].message
    assert evs[3].severity == "warn"


def test_hostname_not_flagged_when_scan_has_none():
    dev = {"ip": "192.168.1.5", "mac": "AA:BB:CC:00:00:05", "hostname": "pi", "status": "online"}
    assert diff_device(dev, _h(hostname=None)) == []


def _p(port, state="open", service="http", product=None, version=None, proto="tcp"):
    return PortResult(port=port, protocol=proto, state=state, service=service,
                      product=product, version=version)


def test_port_opened_closed_changed():
    old = {
        (22, "tcp"): {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "8.9"},
        (80, "tcp"): {"port": 80, "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.24"},
        (443, "tcp"): {"port": 443, "protocol": "tcp", "service": "https"},
    }
    new = [
        _p(22, service="ssh", product="OpenSSH", version="9.6"),   # version bump
        _p(80, product="nginx", version="1.24"),                   # unchanged
        _p(8080, product="Jellyfin"),                              # opened
        _p(9999, state="closed"),                                  # closed ports never count
        # 443 missing -> closed
    ]
    evs = diff_ports("pi (192.168.1.20)", old, new)
    by_kind = {}
    for e in evs:
        by_kind.setdefault(e.kind, []).append(e)
    assert [e.details["port"] for e in by_kind["port_opened"]] == [8080]
    assert [e.details["port"] for e in by_kind["port_closed"]] == [443]
    assert [e.details["port"] for e in by_kind["service_changed"]] == [22]
    assert by_kind["service_changed"][0].details == {
        "port": 22, "protocol": "tcp", "old": "OpenSSH 8.9", "new": "OpenSSH 9.6"}
    assert all(e.message.startswith("pi (192.168.1.20): ") for e in evs)


def test_quick_scan_without_fingerprint_does_not_flag_service_change():
    old = {(22, "tcp"): {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.6"}}
    evs = diff_ports("x", old, [_p(22, service="ssh")])   # no product this time
    assert evs == []


def test_open_filtered_counts_as_open():
    evs = diff_ports("x", {}, [_p(53, state="open|filtered", service="domain", proto="udp")])
    assert [e.kind for e in evs] == ["port_opened"]
    assert evs[0].details["protocol"] == "udp"


def test_merge_keeps_richer_fingerprint():
    old = {"product": "OpenSSH", "version": "9.6", "extrainfo": "Ubuntu", "confidence": 10, "service": "ssh"}
    row = merge_port_rows(old, _p(22, service="ssh"))
    assert row["product"] == "OpenSSH" and row["version"] == "9.6" and row["extrainfo"] == "Ubuntu"
    row2 = merge_port_rows(old, _p(22, service="ssh", product="Dropbear", version="2022"))
    assert row2["product"] == "Dropbear" and row2["extrainfo"] is None
    assert merge_port_rows(None, _p(22))["product"] is None
