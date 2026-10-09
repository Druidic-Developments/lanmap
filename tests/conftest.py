import pytest

from lanmap.config import Settings
from lanmap.db import Store


def host(ip, mac=None, vendor=None, hostname=None, ports=(), os_name=None, state="up"):
    x = f'<host><status state="{state}" reason="arp-response"/>'
    x += f'<address addr="{ip}" addrtype="ipv4"/>'
    if mac:
        x += f'<address addr="{mac}" addrtype="mac"' + (f' vendor="{vendor}"' if vendor else "") + "/>"
    x += "<hostnames>" + (f'<hostname name="{hostname}" type="PTR"/>' if hostname else "") + "</hostnames>"
    if ports:
        x += '<ports><extraports state="closed" count="990"/>'
        for p in ports:
            port, proto, pstate, svc = p[0], p[1], p[2], p[3]
            product = p[4] if len(p) > 4 else None
            version = p[5] if len(p) > 5 else None
            extra = p[6] if len(p) > 6 else None
            x += f'<port protocol="{proto}" portid="{port}"><state state="{pstate}" reason="syn-ack"/>'
            x += f'<service name="{svc}"'
            if product:
                x += f' product="{product}"'
            if version:
                x += f' version="{version}"'
            if extra:
                x += f' extrainfo="{extra}"'
            x += ' conf="10"/></port>'
        x += "</ports>"
    if os_name:
        x += f'<os><osmatch name="{os_name}" accuracy="94"/><osmatch name="Other" accuracy="80"/></os>'
    x += '<times srtt="1500" rttvar="500" to="100000"/></host>'
    return x


def nmaprun(*hosts, start=1700000000, end=1700000060, args="nmap -sn"):
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap" args="{args}" start="{start}" version="7.94">'
            + "".join(hosts) +
            f'<runstats><finished time="{end}" summary="Nmap done"/><hosts up="{len(hosts)}" down="0" total="{len(hosts)}"/></runstats></nmaprun>')


@pytest.fixture
def settings():
    return Settings(subnets=["192.168.1.0/24"], gateway="192.168.1.1", local_ip="192.168.1.20",
                    db_path=":memory:", scan_interval_minutes=0, port_scan_interval_minutes=0,
                    skip_hosts=["192.168.1.99"])


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()
