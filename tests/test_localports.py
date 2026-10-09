from lanmap.localports import parse_ss_output

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
